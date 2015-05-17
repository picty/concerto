open Parsifal
open Getopt
open FileOps
open X509Util

let verbose = ref false
let input_dir = ref ""
let output_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'i') "input-dir" (StringVal input_dir) "set the input directory (certs)";
  mkopt (Some 'o') "output-dir" (StringVal output_dir) "set the output directory (checked-links)";
]


let read_csv in_ops out_ops csvname =
  let f = open_in csvname in
  let rec handle_line f =
    let line = try Some (input_line f) with End_of_file -> None in
    match line with
    | None -> close_in f
    | Some l ->
      match List.map unquote (string_split ':' l) with
      | [subject_h; issuer_h] ->
        let s = sc_of_raw_value subject_h false (in_ops.read_file "certs" subject_h)
        and i = sc_of_raw_value issuer_h false (in_ops.read_file "certs" issuer_h) in
        if check_link_bool (cert_of_sc i) (cert_of_sc s)
        then out_ops.write_line "links" "" [subject_h; issuer_h];
        handle_line f
      | _ -> failwith ("Invalid line (" ^ (quote_string l) ^ ")")
  in
  handle_line f


let _ =
  let csv_files = parse_args ~progname:"checkLinks" options Sys.argv in
  try
    let out_ops = prepare_csv_output_dir !output_dir
    and in_ops = prepare_csv_output_dir !input_dir in
    List.iter (read_csv in_ops out_ops) csv_files;
    in_ops.close_all_files ();
    out_ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
