open Parsifal
open X509
open X509Util
open X509Extensions
open Getopt
open FileOps

let verbose = ref false
let output_dir = ref ""
let input_dir = ref ""
let file_type = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'o') "output-dir" (StringVal output_dir) "set the output directory for parsed data";
  mkopt (Some 'i') "input-dir" (StringVal input_dir) "set the input directory containing raw certs";
  mkopt (Some 't') "file-type" (StringVal file_type) "...";
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

      let ski = match get_subjectKeyIdentifier c.tbsCertificate.extensions with
        | Some (ski, _) -> hexdump ski
        | None -> ""
      and aki_serial, aki_ki = match get_authorityKeyIdentifier c.tbsCertificate.extensions with
        | Some ({keyIdentifier = Some aki_ki; authorityCertSerialNumber = Some aki_serial}, _) -> hexdump aki_serial, hexdump aki_ki
        | Some ({keyIdentifier = Some aki_ki}, _) -> "", hexdump aki_ki
        | Some ({authorityCertSerialNumber = Some aki_serial}, _) -> hexdump aki_serial, ""
        | _ -> "", ""
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
        | _ -> "0");
        ski;
        aki_ki;
        aki_serial;
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

let handle_one_prefix out_ops in_ops file_type prefix =
  let files = in_ops.list_files file_type prefix in
  let handle_one_file (name, _, _) =
    let raw_contents = in_ops.read_file file_type name in
    let sc = sc_of_raw_value name false raw_contents in
    populate_certs_table out_ops sc
  in
  List.iter handle_one_file files


let _ =
  let prefixes = parse_args ~progname:"parse-certs" options Sys.argv in
  try
    let output_ops = prepare_csv_output_dir !output_dir
    and input_ops = prepare_csv_output_dir !input_dir in
    List.iter (handle_one_prefix output_ops input_ops !file_type) prefixes;
    output_ops.close_all_files ();
    input_ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
