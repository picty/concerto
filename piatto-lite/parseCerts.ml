open Parsifal
open X509
open X509Util
open Getopt
open CsvOps

let verbose = ref false
let output_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'o') "output-dir" (StringVal output_dir) "set the output directory for dump2html or dump2csv";
]


let populate_certs_table ops sc =
  let h = hash_of_sc sc in
  if ops.check_key_freshness "certs" h && ops.check_key_freshness "unparsed_certs" h then begin
    try
      let c = cert_of_sc sc in
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

      let not_before, not_after =
        try validity_of_sc sc
        (* TODO: Do better? *)
        with Failure "validity_of_sc" -> -1L, -1L
      in

      let names_extracted = extract_dns_and_ips c in
      
      ops.write_line "certs" h [
      hexdump h;
        (match c.tbsCertificate.version with None -> "1" | Some i -> (string_of_int (i+1)));
        hexdump c.tbsCertificate.serialNumber;
        hexdump subject_hash;
        hexdump issuer_hash;
        Int64.to_string not_before;
        Int64.to_string not_after;
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
        (names_extracted);
    with
    | ParsingException (e, hh) ->
      ops.write_line "unparsed_certs" h [hexdump h; string_of_exception e hh]
    | e ->
      ops.write_line "unparsed_certs" h [hexdump h; Printexc.to_string e]
  end


let handle_one_file ops dirname filename =
  let raw_content = get_file_content (dirname ^ "/" ^ filename) in
  let sc = sc_of_raw_value filename false raw_content in
  populate_certs_table ops sc


let handle_one_dir ops dirname =
  let h = Unix.opendir dirname in
  let rec handle_next_file () =
    let next, again =
      try
        let n = Unix.readdir h in
        let s = Unix.stat (dirname ^ "/" ^ n) in
        if s.Unix.st_kind=Unix.S_REG
        then Some n, true
        else None, true
      with End_of_file -> None, false
    in
    begin
      match next with
      | None -> ()
      | Some name -> handle_one_file ops dirname name
    end;
    if again then handle_next_file ()
  in
  handle_next_file ()



let _ =
  let dirs = parse_args ~progname:"parse-certs" options Sys.argv in
  try
    let ops = prepare_csv_output_dir !output_dir in
    List.iter (handle_one_dir ops) dirs;
    ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
