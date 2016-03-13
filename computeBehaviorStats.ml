(* computeBehaviorStats.ml

   Inputs:
    - answers.csv
    - trusted_chains.csv

   Option:
    - campaign ids
    - trust_flag filters

   Output:
    - stats_behavior_<campaigns>_<values>.csv
 *)

open Getopt
open FileOps
open StatOps

let verbose = ref false
let load_validity = ref false
let data_dir = ref ""
let filters = ref []
let campaigns = ref []
let add_campaign c = campaigns := !campaigns@[c]; ActionDone

type feature =
  | AnswerType
  | AnswerType2
  | FullAnswerType
  | CertChain
let feature_type = ref AnswerType
let set_feature_type f () = feature_type := f

let split_computation = ref 1

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 'f') "filter" (StringList filters) "add a trust flag to filter";
  mkopt (Some 'C') "campaign" (IntFun add_campaign) "add a campaign";

  mkopt None "load-validity" (Set load_validity) "load validity information";

  mkopt (Some 't') "answer-type" (TrivialFun (set_feature_type AnswerType)) "use answer-type (0/1/10/11/20/21) as feature";
  mkopt None "answer-type2" (TrivialFun (set_feature_type AnswerType2)) "use answer-type (J/A/h/H) as feature";
  mkopt None "full-answer-type" (TrivialFun (set_feature_type FullAnswerType)) "use full answer line feature and aggregate the results";
  mkopt None "cert-chain" (TrivialFun (set_feature_type CertChain)) "use certificate chain hash as feature and aggregate the results";

  mkopt None "split-computation" (IntVal split_computation) "Split the computation in n parts";
]


let handle_answer features_by_ip chain_sets chain_validities ip_sets i n = function
  | [campaign_str; ip; _; _; timestamp_str; answer_type_str;
     version_str; ciphersuite_str; alert_level_str; alert_type_str; chain_hash;
     version_compat_str; suite_compat_str; compression_compat_str; extensions_compat_str; _] ->
     if (Hashtbl.hash ip) mod n = i then begin
       let campaign = int_of_string campaign_str
       and timestamp = Int64.of_string timestamp_str
       and answer_compat =
         version_compat_str <> "0" && suite_compat_str <> "0" &&
           compression_compat_str <> "0" && extensions_compat_str <> "0"
       in
       if List.mem campaign !campaigns then begin
         let feature = match !feature_type with
           | AnswerType -> answer_type_str
           | CertChain -> Parsifal.hexparse chain_hash
           | FullAnswerType -> String.concat ":" [answer_type_str; version_str; ciphersuite_str; alert_level_str; alert_type_str; chain_hash]
           | AnswerType2 ->
              match int_of_string answer_type_str, answer_compat with
              | 10, _ | 11, _ -> "A"
              | 20, true | 21, true -> "H"
              | 20, false | 21, false -> "h"
              | _ -> "J"
         in

         let current_list =
           try Hashtbl.find features_by_ip ip
           with Not_found -> []
         in
         Hashtbl.replace features_by_ip ip ((campaign, feature)::current_list);

         let flag_ip trust_flag =
           let result =
             if !load_validity
             then is_flagged_and_valid chain_sets chain_validities trust_flag chain_hash timestamp
             else is_flagged_with chain_sets trust_flag chain_hash
           in
           if result then begin
             let ip_set = Hashtbl.find ip_sets trust_flag in
             Hashtbl.replace ip_sets trust_flag (StringSet.add ip ip_set)
           end
         in
         List.iter flag_ip !filters
       end
     end
  | _ -> raise (InvalidNumberOfFields 16)


let enumerate_stuff ip_sets counts ip feature =
  let get_feature campaign =
    try List.assoc campaign feature
    with Not_found -> "-"
  in
  let k = List.map get_feature !campaigns in
  inc_in_hashtbl counts ("", k);
  let update_flag_trust trust_flag =
    let ip_set = Hashtbl.find ip_sets trust_flag in
    if StringSet.mem ip ip_set
    then inc_in_hashtbl counts (trust_flag, k)
  in
  List.iter update_flag_trust !filters


let count_different_stuff ip_sets counts ip feature =
  let count accu (_, v) =
    if v = "" || List.mem v accu
    then accu
    else v::accu
  in
  let different_hashes = List.fold_left count [] feature in
  let k = [string_of_int (List.length different_hashes)] in
  inc_in_hashtbl counts ("", k);
  let update_flag_trust trust_flag =
    let ip_set = Hashtbl.find ip_sets trust_flag in
    if StringSet.mem ip ip_set
    then inc_in_hashtbl counts (trust_flag, k)
  in
  List.iter update_flag_trust !filters


let write_one_line ops (trust_flag, feature) count =
  let feature_str = match !feature_type with
    | AnswerType -> "answertype"
    | AnswerType2 -> "answertype2"
    | FullAnswerType -> "fullanswertype"
    | CertChain -> "certchain"
  in
  let table_name = "stats_behavior_" ^ (String.concat "_" (List.map string_of_int !campaigns)) ^ "_" ^ feature_str in
  ops.write_line table_name "" ((trust_flag::feature)@[string_of_int count])


let _ =
  let _ = parse_args ~progname:"computeBehaviorStats" options Sys.argv in
  if !data_dir = "" then usage "computeBehaviorStats" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in

    let chain_sets = load_trusted_chains ops !filters in
    if !verbose then print_endline "Trust info loaded.";
    let chain_validities =
      if !load_validity then begin
        let cv = load_chain_validities ops in
        if !verbose then print_endline "Validity info loaded.";
        cv
      end else Hashtbl.create 10
    in

    let counts = Hashtbl.create 100 in
    let update_count = match !feature_type with
      | AnswerType | AnswerType2 -> enumerate_stuff
      | CertChain | FullAnswerType -> count_different_stuff
    in

    let handle_computation i n =
      let features_by_ip = Hashtbl.create 1000
      and ip_sets = Hashtbl.create 10 in
      List.iter (fun trust_flag -> Hashtbl.add ip_sets trust_flag StringSet.empty) !filters;
      ops.iter_lines "answers" (handle_answer features_by_ip chain_sets chain_validities ip_sets i n);

      Hashtbl.iter (update_count ip_sets counts) features_by_ip;
    in

    if !split_computation > 1 then begin
      for i = 0 to !split_computation do
        handle_computation i !split_computation
      done
    end else handle_computation 0 1;

    Hashtbl.iter (write_one_line ops) counts;

    ops.close_all_files ()
  with
    | e -> prerr_endline (Printexc.to_string e); exit 1
