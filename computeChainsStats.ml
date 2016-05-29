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
    - stats_key_robustness.csv
    - stats_validity_period.csv
  *)

open Getopt
open FileOps
open ConcertoUtils
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


let update_count chain_qualities counts = function
  | [_; _; _; _; _; _; _; _; _; _; _; ""; _; _; _; _; _] -> ()
  | [campaign_str; _; _; _; timestamp_str; _; _; _; _; _; _;
     chain_hash; _; _; _; _; _] ->
     let campaign = int_of_string campaign_str in
     let (q, nb, na, algos, flags) = Hashtbl.find chain_qualities chain_hash in
     let computed_v = Int64.to_int (Int64.div (Int64.add (Int64.sub na nb) 86399L) 86400L) in
     let validity = if computed_v < 0 then 0 else computed_v
     and timestamp = Int64.of_string timestamp_str
     and quality = char_of_chain_quality q in

     let add_for_trust_flag trust_flag =
       increment campaign trust_flag "chain_quality" counts (String.make 1 quality);
       increment campaign trust_flag "validity_period" counts (string_of_int validity);
       increment campaign trust_flag "key_robustness" counts (string_of_key_typesize algos)
     in

     add_for_trust_flag "";
     if timestamp >= nb && timestamp <= na
     then List.iter add_for_trust_flag flags

  | _ -> raise (InvalidNumberOfFields 17)


let write_one_value ops (campaign, trust_flag, stat_kind) v count =
  ops.write_line ("stats_" ^ stat_kind) "" [string_of_int campaign; trust_flag; v; string_of_int count]

let write_one_hashtbl ops k h =
  Hashtbl.iter (write_one_value ops k) h


let _ =
  let _ = parse_args ~progname:"computeChainsStats" options Sys.argv in
  if !data_dir = "" then usage "computeChainsStats" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in

    let trusted_built_chains = load_trusted_built_chains ops !filters in
    if !verbose then print_endline "Trust info loaded.";
    let chain_qualities = load_chain_qualities trusted_built_chains ops in
    if !verbose then print_endline "Chain details loaded.";

    let counts = Hashtbl.create 10 in
    ops.iter_lines "answers" (update_count chain_qualities counts);
    Hashtbl.iter (write_one_hashtbl ops) counts;

    ops.close_all_files ()
  with
    | e -> prerr_endline (Printexc.to_string e); exit 1
