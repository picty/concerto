(* inject.ml

   Argument:
    - binary files

   Outputs:
    - copy in raw/<type>
 *)

open Parsifal
open Getopt
open X509Util
open FileOps


let data_dir = ref ""
let filetype = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 't') "file-type" (StringVal filetype) "set the file type";
]

let rec handle_one_file ops filename =
  let raw_cert = get_file_content filename in
  let sc = sc_of_raw_value filename false raw_cert in
  ops.dump_file !filetype (hexdump (hash_of_sc sc)) (raw_value_of_sc sc)


let _ =
  let cert_files = parse_args ~progname:"inject" options Sys.argv in
  if !data_dir = "" then usage "inject" options (Some "Please provide a valid data directory");
  if !filetype = "" then usage "inject" options (Some "Please provide a type");
  try
    let ops = prepare_data_dir !data_dir in
    List.iter (handle_one_file ops) cert_files;
    ops.close_all_files ()
  with
    | e ->
      let current_prog = String.concat " " (Array.to_list Sys.argv) in
      prerr_endline ("[" ^ current_prog ^ "] " ^ (Printexc.to_string e)); exit 1
