(* checkLinks.ml

   Inputs:
    - possible_links.csv
    - certs/

   Outputs:
    - links.csv
 *)

open Parsifal
open Getopt
open FileOps
open X509Util

let data_dir = ref ""
let suffix = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";

  mkopt None "suffix" (StringVal suffix) "adds a suffix to the CSV files used";
]


let check_one_line ops links_filename = function
  | [subject_h; issuer_h] ->
     let s = sc_of_raw_value subject_h false (ops.read_file "certs" subject_h)
     and i = sc_of_raw_value issuer_h false (ops.read_file "certs" issuer_h) in
     if check_link_bool (cert_of_sc i) (cert_of_sc s)
     then ops.write_line links_filename "" [subject_h; issuer_h]
  | _ -> raise (InvalidNumberOfFields 2)


let _ =
  relax_x509_constraints ();
  accept_v1_cas := true;

  (* TODO: Check that this _ is [] *)
  let _ = parse_args ~progname:"checkLinks" options Sys.argv in
  if !data_dir = "" then usage "checkLinks" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in
    ops.iter_lines ("possible_links" ^ !suffix) (check_one_line ops ("links" ^ !suffix));
    ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
