(* computeChainsStats.ml

   Inputs:
    - answers.csv
    - trusted_chains.csv
    - built_chains.csv

   Option:
    - campaign id
    - trust_flag filters

   Output:
    - stats_chain_quality.csv
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


let update_count chain_sets chain_qualities counts = function
  | [campaign_str; _; _; _; timestamp_str; answer_type; version; ciphersuite; _; _;
     chain_hash; _; _; _; _; _] ->
     let campaign = int_of_string campaign_str in
     let best_quality =
       try
         let q, _, _ = Hashtbl.find chain_qualities chain_hash in
         int_of_chain_quality q
       with Not_found -> -1
     in
     (* TODO: Take timestamp into account *)
     (* and timestamp = Int64.of_string timestamp_str in *)
     (* let chain_quality = Hashtbl.find_all chain_details chain_hash in *)
     (* let check_validity (_, _, _, _, nb, na) = timestamp >= nb && timestamp <= na in *)
     (* let valid_chain_details = List.filter check_validity chain_details in *)
     (* let best_quality = match List.rev (List.sort compare_chain_quality (List.map chain_quality_of_details valid_chain_details)) with *)
     (*   | [] -> -1 *)
     (*   | x::_ -> int_of_chain_quality x *)
     (* in *)

     let add_for_trust_flag trust_flag =
       increment campaign trust_flag "chain_quality" counts [string_of_int best_quality]
     in

     add_for_trust_flag "";

     let increment_for_flag trust_flag =
       if is_flagged_with chain_sets trust_flag chain_hash
       then add_for_trust_flag trust_flag
     in
     List.iter increment_for_flag !filters

  | _ -> raise (InvalidNumberOfFields 16)


let write_one_value ops (campaign, trust_flag, stat_kind) value_list count =
  ops.write_line ("stats_" ^ stat_kind) "" ([string_of_int campaign; trust_flag]@value_list@[string_of_int count])

let write_one_hashtbl ops k h =
  Hashtbl.iter (write_one_value ops k) h


let _ =
  let _ = parse_args ~progname:"computeChainsStats" options Sys.argv in
  if !data_dir = "" then usage "computeChainsStats" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in

    let chain_sets = load_trusted_chains ops !filters in
    if !verbose then print_endline "Trust info loaded.";
    let chain_qualities = load_chain_qualities ops in
    if !verbose then print_endline "Chain details loaded.";

    let counts = Hashtbl.create 10 in
    ops.iter_lines "answers" (update_count chain_sets chain_qualities counts);
    Hashtbl.iter (write_one_hashtbl ops) counts;

    ops.close_all_files ()
  with
    | e -> prerr_endline (Printexc.to_string e); exit 1
