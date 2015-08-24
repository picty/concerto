(* injectStimulus.ml

   Argument:
    - stimulus files

   Outputs:
    - stimuli
    - stimuli.csv
    - stimuli_suites.csv
    - stimuli_compressions.csv
    - stimuli_extensions.csv
 *)

open Parsifal
open TlsEnums
open Stimulus
open Getopt
open FileOps


let data_dir = ref ""
let stimulus_name = ref None
let stimulus_id = ref None
let update r v = r := Some v; ActionDone

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 'n') "name" (StringFun (update stimulus_name)) "set the stimulus name";
  mkopt (Some 'i') "identifier" (IntFun (update stimulus_id)) "set the stimulus id";
]


let _ =
  let stimulus_file = parse_args ~progname:"injectStimulus" options Sys.argv in
  if !data_dir = "" then usage "injectStimulus" options (Some "Please provide a valid data directory");
  let stimulus_id_str = match !stimulus_id with
    | None -> usage "injectStimulus" options (Some "Please provide a stimulus id")
    | Some id -> string_of_int id
  in
  let stimulus_real_name, stimulus_raw_content = match stimulus_file, !stimulus_name with
    | [filename], None -> filename, get_file_content filename
    | [filename], Some name -> name, get_file_content filename
    | _ -> usage "injectStimulus" options (Some "Please provide exactly one argument (the stimulus)")
  in
  try
    let ops = prepare_data_dir !data_dir in
    ops.dump_file "stimuli" (hexdump (CryptoUtil.sha1sum stimulus_raw_content)) stimulus_raw_content;
    let min_version, max_version, suites, compressions, extensions = Stimulus.parse_stimulus stimulus_raw_content in
    ops.write_line "stimuli" "" [
      stimulus_id_str; stimulus_real_name;
      string_of_int min_version; string_of_int max_version;
    ];
    let write_line csv v = ops.write_line csv "" [stimulus_id_str; string_of_int v] in
    List.iter (write_line "stimuli_suites") suites;
    List.iter (write_line "stimuli_compressions") compressions;
    List.iter (write_line "stimuli_extensions") extensions;
    ops.close_all_files ()
  with
    | e ->
      let current_prog = String.concat " " (Array.to_list Sys.argv) in
      prerr_endline ("[" ^ current_prog ^ "] " ^ (Printexc.to_string e)); exit 1
