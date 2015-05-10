open FileOps
open Getopt

let input_dir = ref ""
let output_dir = ref ""
let filetype = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'i') "input-dir" (StringVal input_dir) "set the input directory";
  mkopt (Some 'o') "output-dir" (StringVal output_dir) "set the output directory";
  mkopt (Some 't') "file-type" (StringVal filetype) "set the filetype to merge";
]


let _ =
  let prefixes = parse_args ~progname:"mergeRawFiles" options Sys.argv in
  try
    let in_ops = prepare_csv_output_dir !input_dir
    and out_ops = prepare_csv_output_dir !output_dir in
    let copy_file (name, _, _) =
      let contents = in_ops.read_file !filetype name in
      out_ops.dump_file !filetype name contents
    in
    List.iter (fun prefix -> List.iter copy_file (in_ops.list_files !filetype prefix)) prefixes;
    in_ops.close_all_files ();
    out_ops.close_all_files ()
  with
    | e -> prerr_endline (Printexc.to_string e); exit 1
