open FileOps
open Getopt

let verbose = ref true
let input_dirs = ref []
let output_dir = ref ""
let filetype = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "verbose mode";
  mkopt (Some 'i') "input-dir" (StringList input_dirs) "set the input directory";
  mkopt (Some 'o') "output-dir" (StringVal output_dir) "set the output directory";
  mkopt (Some 't') "file-type" (StringVal filetype) "set the filetype to merge";
]


let _ =
  let prefixes = parse_args ~progname:"mergeRawFiles" options Sys.argv in
  try
    let out_ops = prepare_csv_output_dir !output_dir in
    let handle_input_dir input_dir =
      print_string ("Handling " ^ input_dir ^ "... ");
      let in_ops = prepare_csv_output_dir input_dir in
      let copy_file (name, _, _) =
        let contents = in_ops.read_file !filetype name in
        out_ops.dump_file !filetype name contents
      in
      List.iter (fun prefix -> List.iter copy_file (in_ops.list_files !filetype prefix)) prefixes;
      in_ops.close_all_files ();
      print_endline "OK."
    in
    List.iter handle_input_dir !input_dirs;
    out_ops.close_all_files ()
  with
  | e ->
    let current_prog = String.concat " " (Array.to_list Sys.argv) in
    prerr_endline ("[" ^ current_prog ^ "] " ^ (Printexc.to_string e)); exit 1
