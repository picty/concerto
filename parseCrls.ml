(* parseCerts.ml

   Args:
    - crl files

   Outputs:
    - revoked_certs.csv
 *)

open Parsifal
open Crl
open Getopt
open FileOps

let data_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
]


let handle_one_file ops (name, _, _) =
  let raw_contents = ops.read_file "crls" name in
  let i = input_of_string name raw_contents in
  try
    let crl = parse_certificateList i in

    let issuer = crl.tbsCertList.issuer in
    let issuer_raw = exact_dump X509Basics.dump_distinguishedName issuer in
    let issuer_hash = CryptoUtil.sha1sum issuer_raw in

    let handle_one_revoked_cert rc =
      ops.write_line "revoked_certs" "" [hexdump issuer_hash; hexdump rc.userCertificate]
    in

    match crl.tbsCertList.revokedCertificates with
    | None -> ()
    | Some rcs -> List.iter handle_one_revoked_cert rcs
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h)
    | e -> prerr_endline (Printexc.to_string e); exit 1

let handle_one_prefix ops prefix =
  try
    let files = ops.list_files_by_prefix "crls" prefix in
    List.iter (handle_one_file ops) files
  with
    Not_found -> ()


let _ =
  let prefixes = parse_args ~progname:"parseCrls" options Sys.argv in
  if !data_dir = "" then usage "parseCrls" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in
    List.iter (handle_one_prefix ops) prefixes;
    ops.close_all_files ()
  with
    | e -> prerr_endline (Printexc.to_string e); exit 1
