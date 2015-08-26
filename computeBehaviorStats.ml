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
 *)

open Getopt
open FileOps
open StatOps

let verbose = ref false
let data_dir = ref ""
let filters = ref []

module Campaign = struct
  type t = int
  let compare x y = Pervasives.compare x y
end

module CampaignSet = Set.Make(Campaign)


let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 'f') "filter" (StringList filters) "add a trust flag to filter";
]


let handle_answer answer_types_by_ip chain_sets ip_sets campaigns = function
  | [campaign_str; ip; _; _; _; answer_type_str; _; _; _; _; chain_hash; _; _; _; _] ->
     let campaign = int_of_string campaign_str
     and answer_type = int_of_string answer_type_str in

     let current_list =
       try Hashtbl.find answer_types_by_ip ip
       with Not_found -> []
     in
     Hashtbl.replace answer_types_by_ip ip ((campaign, answer_type)::current_list);

     let flag_ip trust_flag =
       if is_flagged_with chain_sets trust_flag chain_hash
       then begin
         let ip_set = Hashtbl.find ip_sets trust_flag in
         Hashtbl.replace ip_sets trust_flag (StringSet.add ip ip_set)
       end
     in
     List.iter flag_ip !filters;

     CampaignSet.add campaign campaigns

  | _ -> raise (InvalidNumberOfFields 15)


let update_count campaigns ip_sets counts ip answer_types =
  let get_answer_type campaign =
    try string_of_int (List.assoc campaign answer_types)
    with Not_found -> "-"
  in
  let k = List.map get_answer_type campaigns in
  inc_in_hashtbl counts ("", k);
  let update_flag_trust trust_flag =
    let ip_set = Hashtbl.find ip_sets trust_flag in
    if StringSet.mem ip ip_set
    then inc_in_hashtbl counts (trust_flag, k)
  in
  List.iter update_flag_trust !filters
        

let write_one_line ops campaigns (trust_flag, answer_types) count =
  let table_name = "stats_behavior_" ^ (String.concat "_" (List.map string_of_int campaigns)) in
  ops.write_line table_name "" ((trust_flag::answer_types)@[string_of_int count])


let _ =
  let _ = parse_args ~progname:"computeStats" options Sys.argv in
  if !data_dir = "" then usage "computeStats" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in

    let chain_sets = load_trusted_chains ops !filters in
    if !verbose then print_endline "Trust info loaded.";

    let answer_types_by_ip = Hashtbl.create 1000
    and ip_sets = Hashtbl.create 10 in
    List.iter (fun trust_flag -> Hashtbl.add ip_sets trust_flag StringSet.empty) !filters;
    let campaign_set = ops.iter_lines_accu "answers" (handle_answer answer_types_by_ip chain_sets ip_sets) (CampaignSet.empty) in
    let campaigns = CampaignSet.elements campaign_set in

    let counts = Hashtbl.create 100 in
    Hashtbl.iter (update_count campaigns ip_sets counts) answer_types_by_ip;
    Hashtbl.iter (write_one_line ops campaigns) counts;

    ops.close_all_files ()
  with
    | e -> prerr_endline (Printexc.to_string e); exit 1
