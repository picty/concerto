(* computeStats.ml

   Inputs:
    - answers.csv
    - trusted_chains.csv

   Option:
    - campaign id
    - trust_flag filters

   Output:
    - stats_answertypes.csv
    - stats_versions.csv
    - stats_ciphersuites.csv
    - stats_rfc5746.csv
 *)

open Getopt
open FileOps
open StatOps

let verbose = ref false
let data_dir = ref ""
let filters = ref []

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 'f') "filter" (StringList filters) "add a trust flag to filter";
]


let increment campaign trust_flag stat_kind counts v =
  let h =
    try Hashtbl.find counts (campaign, trust_flag, stat_kind)
    with Not_found ->
      let new_h = Hashtbl.create 10 in
      Hashtbl.replace counts (campaign, trust_flag, stat_kind) new_h;
      new_h
  in
  inc_in_hashtbl h v


let update_count chain_sets chain_validities counts = function
  | [campaign_str; _; _; _; timestamp_str; answer_type; version; ciphersuite; _; _; chain_hash;
     version_compat_str; suite_compat_str; compression_compat_str; extensions_compat_str; is_rfc5746_supported] ->
     let campaign = int_of_string campaign_str
     and timestamp = Int64.of_string timestamp_str
     and answer_compat =
       version_compat_str <> "0" && suite_compat_str <> "0" &&
         compression_compat_str <> "0" && extensions_compat_str <> "0"
     in
     let add_for_trust_flag trust_flag =
       increment campaign trust_flag "answertypes" counts [answer_type; if answer_compat then "1" else "0"];
       if answer_type = "20" || answer_type = "21" then begin
         increment campaign trust_flag "versions" counts [version; version_compat_str];
         increment campaign trust_flag "ciphersuites" counts [ciphersuite; suite_compat_str];
         increment campaign trust_flag "rfc5746" counts [is_rfc5746_supported];
       end
     in

     add_for_trust_flag "";

     let increment_for_flag trust_flag =
       if is_flagged_and_valid chain_sets chain_validities trust_flag chain_hash timestamp
       then add_for_trust_flag trust_flag
     in
     List.iter increment_for_flag !filters

  | _ -> raise (InvalidNumberOfFields 16)


let write_one_value ops (campaign, trust_flag, stat_kind) value_list count =
  ops.write_line ("stats_" ^ stat_kind) "" ([string_of_int campaign; trust_flag]@value_list@[string_of_int count])

let write_one_hashtbl ops k h =
  Hashtbl.iter (write_one_value ops k) h


let _ =
  let _ = parse_args ~progname:"computeStats" options Sys.argv in
  if !data_dir = "" then usage "computeStats" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in

    let chain_sets = load_trusted_chains ops !filters in
    if !verbose then print_endline "Trust info loaded.";
    let chain_validities = load_chain_validities ops in
    if !verbose then print_endline "Validity info loaded.";

    let counts = Hashtbl.create 10 in
    ops.iter_lines "answers" (update_count chain_sets chain_validities counts);
    Hashtbl.iter (write_one_hashtbl ops) counts;

    ops.close_all_files ()
  with
    | e -> prerr_endline (Printexc.to_string e); exit 1
