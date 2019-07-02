(* listV1cert.ml

   Argument:
    - binary files

   Outputs:
    - v1cas.csv
 *)

open Parsifal
open Getopt
open FileOps
open X509Util
open X509


let data_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
]

let handle_one_file ops filename =
  let raw_file = get_file_content filename in
  let sc = sc_of_raw_value filename false raw_file in
  let c = cert_of_sc sc in
  if c.tbsCertificate.version = None
  then begin
    let h = hash_of_sc sc in
    if ops.check_key_freshness "v1cas" h
    then ops.write_line "v1cas" h [hexdump h]
  end

let _ =
  relax_x509_constraints ();
  let raw_files = parse_args ~progname:"listV1cert" options Sys.argv in
  if !data_dir = "" then usage "listV1cert" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in
    List.iter (handle_one_file ops) raw_files;
    ops.close_all_files ()
  with
    | e ->
      let current_prog = String.concat " " (Array.to_list Sys.argv) in
      prerr_endline ("[" ^ current_prog ^ "] " ^ (Printexc.to_string e)); exit 1
