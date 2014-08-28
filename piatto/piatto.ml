open Parsifal
open X509
open X509Util
open Getopt
open Base64

open Lwt
open LwtUtil
open AnswerDump
open Tls
open TlsEngineNG


let verbose = ref false
let base64 = ref true
let cas = ref []
let output_dir = ref ""

let add_ca filename =
  cas := filename::!cas;
  ActionDone

let cas_filename = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt None "pem" (Set base64) "use PEM format (default)";
  mkopt None "der" (Clear base64) "use DER format";

  mkopt None "ca" (StringFun add_ca) "select a CA file";
  mkopt None "ca-bundle" (StringVal cas_filename) "select an intermediate CAs bundle file";

  mkopt (Some 'o') "output-dir" (StringVal output_dir) "set the output directory for dump2html or dump2csv";
]




(* CSV stuff *)

type csv_ops = {
  check_key_freshness : string -> string -> bool;
  close_all_files : unit -> unit;
  write_line : string -> string -> string list -> unit;
  dump_file : string -> string -> unit;
}

let prepare_csv_output_dir () =
  Unix.mkdir !output_dir 0o755;
  Unix.mkdir (!output_dir ^ "/raw") 0o755;
  let open_files = Hashtbl.create 10 in
  let open_file csv_name =
    try
      Hashtbl.find open_files csv_name
    with
      Not_found ->
	let f = open_out (!output_dir ^ "/" ^ csv_name ^ ".csv") in
	let keys = Hashtbl.create 100 in
	Hashtbl.replace open_files csv_name (f, keys);
	f, keys
  in
  let check_key_freshness csv_name key =
    let _, keys = open_file csv_name in
    not (Hashtbl.mem keys key)
  and write_line csv_name key line =
    let f, keys = open_file csv_name in
    output_string f (String.concat ":" (List.map quote_string line));
    output_string f "\n";
    Hashtbl.replace keys key ()
  and close_all_files () =
    let close_file _ (f, _) = close_out f in
    Hashtbl.iter close_file open_files;
    Hashtbl.clear open_files
  and dump_file name content =
    let f = open_out (!output_dir ^ "/raw/" ^ name) in
    output_string f content;
    close_out f
  in
  { check_key_freshness; write_line;
    close_all_files; dump_file }


let string_of_der_time = function
  | X509Basics.UTCTime t -> Asn1PTypes.string_of_time_content t
  | X509Basics.GeneralizedTime t -> Asn1PTypes.string_of_time_content t
  | X509Basics.UnparsedTime _ -> "UNPARSED TIME"



let populate_certs_table ops store sc =
  let h = hash_of_sc sc
  and c = cert_of_sc sc in
  if ops.check_key_freshness "certs" h then begin
    ops.dump_file (hexdump h) (raw_value_of_sc sc);

    let subject = X509Basics.string_of_distinguishedName c.tbsCertificate.subject
    and subject_hash = subject_hash_of_sc sc
    and issuer = X509Basics.string_of_distinguishedName c.tbsCertificate.issuer
    and issuer_hash = issuer_hash_of_sc sc in

    let key_type, rsa_modulus, rsa_exponent =
      match c.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey with
      | DSA _ -> "DSA", "", ""
      | DH _ -> "DH", "", ""
      | RSA rsa_key ->
	"RSA", hexdump rsa_key.Pkcs1.p_modulus,
	hexdump rsa_key.Pkcs1.p_publicExponent
      | UnparsedPublicKey _ -> "Unknown", "", ""
    in

    ops.write_line "certs" h [
      hexdump h;
      (match c.tbsCertificate.version with None -> "1" | Some i -> (string_of_int (i+1)));
      hexdump c.tbsCertificate.serialNumber;
      hexdump subject_hash;
      hexdump issuer_hash;
      string_of_der_time (c.tbsCertificate.validity.X509Basics.notBefore);
      string_of_der_time (c.tbsCertificate.validity.X509Basics.notAfter);
      key_type;
      rsa_modulus;
      rsa_exponent;
      (match get_basicConstraints c.tbsCertificate.extensions with
      | Some ({X509Extensions.cA = Some true}, _) -> "1"
      | _ -> "0")
    ];

    if ops.check_key_freshness "dns" subject_hash
    then ops.write_line "dns" subject_hash [hexdump subject_hash; subject];
    if ops.check_key_freshness "dns" issuer_hash
    then ops.write_line "dns" issuer_hash [hexdump issuer_hash; issuer];

    List.iter (fun (name_type, name_value) ->
      ops.write_line "names" "" [hexdump h; name_type; name_value])
      (extract_dns_and_ips c);

    let possible_issuers = find_by_subject_hash store issuer_hash in
    List.iter (fun possible_issuer ->
      if sc_check_link possible_issuer sc
      then ops.write_line "links" "" [hexdump (hash_of_sc possible_issuer); hexdump h]
    ) possible_issuers
  end


let populate_chains_table ops store chain_hash i (grade, built_chain) =
  let not_before, not_after = compute_chain_validity built_chain.chain in
  ops.write_line "built_chains" "" [
    hexdump chain_hash;
    string_of_int i;
    grade;
    if built_chain.complete then "1" else "0";
    if built_chain.trusted then "1" else "0";
    if built_chain.ordered then "1" else "0";
    Int64.to_string not_before;
    Int64.to_string not_after;
  ];
  List.iteri (fun pos_in_chain -> fun sc ->
    ops.write_line "built_links" "" [
      hexdump chain_hash;
      string_of_int i;
      string_of_int pos_in_chain;
      (match sc.pos_in_hs_msg with None -> "-" | Some pos_in_msg -> string_of_int pos_in_msg);
      hexdump (hash_of_sc sc)
    ]) (List.rev built_chain.chain);
  List.iter (fun sc ->
    ops.write_line "unused_certs" "" [
      hexdump chain_hash;
      string_of_int i;
      (match sc.pos_in_hs_msg with None -> "-" | Some pos_in_msg -> string_of_int pos_in_msg);
      hexdump (hash_of_sc sc)
    ]) built_chain.unused_certs;
  List.iter (populate_certs_table ops store) (List.filter (fun sc -> sc.pos_in_hs_msg = None) built_chain.chain)


let rec csv_handle_one_file ops store input =
  let finalize_ok answer =
    let ctx = empty_context (default_prefs DummyRNG) in
    let ip_str = string_of_v2_ip answer.ip_addr in
    let campaign = string_of_int answer.campaign in
    enrich_record_content := true;
    let answer_input = input_of_string ip_str answer.content in
    ignore (parse_all_records ServerToClient (Some ctx) answer_input);

    let certs = List.mapi (sc_of_cert_in_hs_msg false ip_str) ctx.future.f_certificates in
    let chain_hash = CryptoUtil.sha1sum (String.concat "" (List.map hash_of_sc certs)) in
    if ops.check_key_freshness "answers" (ip_str ^ campaign ^ answer.name) then begin
      ops.write_line "answers" (ip_str ^ campaign ^ answer.name)
        [campaign; ip_str; string_of_int answer.port; answer.name;
         Int64.to_string answer.timestamp; hexdump chain_hash];

      if ops.check_key_freshness "chains" chain_hash then begin
	List.iteri (fun i -> fun sc -> ops.write_line "chains" chain_hash
	  [hexdump chain_hash; string_of_int i; hexdump (hash_of_sc sc)]) certs;

	let built_chains = build_certchain certs store in
	List.iteri (populate_chains_table ops store chain_hash) (rate_and_sort_chains built_chains);
	List.iter (populate_certs_table ops store) certs
      end
    end;
    csv_handle_one_file ops store input

  and finalize_nok = function
    | (ParsingException _) as e ->
      if input.lwt_eof && (input.string_input.cur_length = 0)
      then return ()
      else fail e
    | e -> fail e

  in try_bind (fun () -> lwt_parse_wrapper parse_answer_dump_v2 input) finalize_ok finalize_nok





let rec cas_handle_one_file certs_seen cas_file input =
  let finalize_ok answer =
    let ctx = empty_context (default_prefs DummyRNG) in
    let ip_str = string_of_v2_ip answer.ip_addr in
    enrich_record_content := true;
    let answer_input = input_of_string ip_str answer.content in
    ignore (parse_all_records ServerToClient (Some ctx) answer_input);
    let extract_cert = function
      | PTypes.Parsed (Some raw, parsed_c) -> raw, Some parsed_c
      | PTypes.Parsed (None, _) -> failwith "Should not happen: certificates must not be parsed until it's time."
      | PTypes.Unparsed c -> c, None
    in
    let certs = List.map extract_cert ctx.future.f_certificates in
    let o = POutput.create () in
    List.iter (fun (c, parsed_opt) ->
      let h = CryptoUtil.sha1sum c in
      if not (Hashtbl.mem certs_seen h) then begin
	Hashtbl.replace certs_seen h ();
	try
	  let parsed_c = match parsed_opt with
	    | None -> parse_certificate (input_of_string (hexdump h) c)
	    | Some p -> p
	  in
	  match get_basicConstraints parsed_c.tbsCertificate.extensions with
	  | Some ({X509Extensions.cA = Some true}, _) ->
	    BasePTypes.dump_varlen_binstring BasePTypes.dump_uint32 o c
	  | _ -> ()
	with _ -> ()
      end) certs;
    POutput.output_buffer cas_file o;
    cas_handle_one_file certs_seen cas_file input

  and finalize_nok = function
    | (ParsingException _) as e ->
      if input.lwt_eof && (input.string_input.cur_length = 0)
      then return ()
      else fail e
    | e -> fail e

  in try_bind (fun () -> lwt_parse_wrapper parse_answer_dump_v2 input) finalize_ok finalize_nok



let load_cas_bundle trusted store bundle_filename =
  let input = string_input_of_filename bundle_filename in
  let certs = BasePTypes.parse_rem_list ""
    (BasePTypes.parse_varlen_container BasePTypes.parse_uint32 "cert_container"
       (parse_smart_cert trusted)) input in
  List.iter (add_to_store store) certs



let parse_fun trusted c =
  if !base64
  then parse_base64_container AnyHeader "base64_container" (parse_smart_cert trusted) c
  else parse_smart_cert trusted c

let parse_and_number i filename =
  let sc = parse_fun false (string_input_of_filename filename) in
  sc.pos_in_hs_msg <- Some i;
  sc


let _ =
  let ca_store = X509Util.mk_cert_store 100 in
  let args = parse_args ~progname:"x509check" options Sys.argv in
  try
    let ca_roots = List.map
      (fun ca_fn -> parse_fun true (string_input_of_filename ca_fn))
      (List.rev !cas)
    in
    List.iter (add_to_store ca_store) ca_roots;
    match args with
    | "rfc-check"::certs ->
      let parsed_certs = List.mapi parse_and_number certs in
      print_chain (check_rfc_certchain parsed_certs ca_store)

    | "laxist-check"::certs ->
      let parsed_certs = List.mapi parse_and_number certs in
      if !cas_filename <> ""
      then load_cas_bundle false ca_store !cas_filename;
      let chains = build_certchain parsed_certs ca_store in
      List.iter (fun (g, c) -> print_endline g; print_chain c; print_newline ()) (rate_and_sort_chains chains)

    | "dump2csv"::dump_files ->
      let ops = prepare_csv_output_dir () in
      if !cas_filename <> ""
      then load_cas_bundle false ca_store !cas_filename;
      let open_files = function
	| [] -> input_of_channel ~verbose:(!verbose) "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
	| _ -> Lwt_list.map_s input_of_filename dump_files
      in
      Lwt_unix.run (open_files dump_files >>= Lwt_list.iter_s (csv_handle_one_file ops ca_store));
      ops.close_all_files ()

    | "extract-cas"::dump_files ->
      let certs_seen = Hashtbl.create 1000 in
      let cas_file = open_out !cas_filename in
      let open_files = function
	| [] -> input_of_channel ~verbose:(!verbose) "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
	| _ -> Lwt_list.map_s input_of_filename dump_files
      in
      Lwt_unix.run (open_files dump_files >>= Lwt_list.iter_s (cas_handle_one_file certs_seen cas_file))

    | "mk-bundle"::cert_files ->
      let bundle = open_out !cas_filename in
      let o = POutput.create () in
      let parsed_certs = List.map (fun fn -> parse_fun false (string_input_of_filename fn)) cert_files in
      List.iter (fun c -> BasePTypes.dump_varlen_binstring BasePTypes.dump_uint32 o (raw_value_of_sc c)) parsed_certs;
      POutput.output_buffer bundle o

    | ["show-cas"] ->
      if !cas_filename <> ""
      then load_cas_bundle false ca_store !cas_filename;
      store_iter (fun sc ->
	let h = hash_of_sc sc and c = cert_of_sc sc in
	print_string (hexdump h);
	print_char ':';
	if sc.trusted_cert then print_char '*';
	print_char ':';
	print_endline (quote_string (X509Basics.string_of_distinguishedName c.tbsCertificate.subject))
      ) ca_store

    | _ ->
      usage "x509check" options
	(Some "Please provide a valid command (rfc-check, laxist-check, extract-cas, show-cas, mk-bundle or dump2csv).")

  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
