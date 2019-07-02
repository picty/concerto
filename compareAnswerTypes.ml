(* computeAnswerTypes.ml

   Inputs:
    - answers.csv
    - trusted_chains.csv

   Option:
    - campaign ids (reference + campaigns to test)
    - trust_flag filters

   Output:
    - stats_answertype_comparison_<campaigns>.csv
 *)

open Getopt
open FileOps
open StatOps

let verbose = ref false
let load_validity = ref false
let data_dir = ref ""
let subsets = ref []
let ref_campaign = ref (-1)

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 'f') "filter" (StringList subsets) "add a trust flag/subset to filter";
  mkopt (Some 'R') "reference" (IntVal ref_campaign) "set the reference campaign";

  mkopt None "load-validity" (Set load_validity) "load validity information";
]


let compute_reference ref_data chain_sets chain_validities = function
  | [campaign_str; ip; _; _; timestamp_str; answer_type_str;
     _; _; _; _; _; chain_hash;
     version_compat_str; suite_compat_str; compression_compat_str; extensions_compat_str; _] ->
     let campaign = int_of_string campaign_str
     and answer_type = int_of_string answer_type_str in
     if campaign = !ref_campaign && answer_type <> 0 then begin
       let timestamp = Int64.of_string timestamp_str
       and answer_compat =
         version_compat_str <> "0" && suite_compat_str <> "0" &&
           compression_compat_str <> "0" && extensions_compat_str <> "0"
       in
       
       let compute_trust_flag trust_flag =
         if !load_validity
         then is_flagged_and_valid chain_sets chain_validities trust_flag chain_hash timestamp
         else is_flagged_with chain_sets trust_flag chain_hash
       in
       let trust_flags = List.map compute_trust_flag !subsets in
       Hashtbl.replace ref_data ip (answer_type, answer_compat, trust_flags)
     end
  | _ -> raise (InvalidNumberOfFields 17)


let handle_answer ref_data stats campaigns_to_test = function
  | [campaign_str; ip; _; _; _; answer_type_str;
     _; _; _; _; _; _;
     version_compat_str; suite_compat_str; compression_compat_str; extensions_compat_str; _] ->
     let campaign = int_of_string campaign_str in
     if List.mem campaign campaigns_to_test then begin
       let ref_at, ref_compat, ref_trust_flags =
         try Hashtbl.find ref_data ip
         with Not_found -> 0, true, List.map (fun _ -> false) !subsets
       and answer_type = int_of_string answer_type_str
       and answer_compat =
         version_compat_str <> "0" && suite_compat_str <> "0" &&
           compression_compat_str <> "0" && extensions_compat_str <> "0"
       in
       let key = ref_at, ref_compat, answer_type, answer_compat in

       let campaign_hashtbl = Hashtbl.find stats campaign in
       let rec populate_stats = function
         | f::fs, true::ref_fs ->
            let h = Hashtbl.find campaign_hashtbl f in
            inc_in_hashtbl h key;
            populate_stats (fs, ref_fs)
         | _::fs, false::ref_fs -> populate_stats (fs, ref_fs)
         | [], [] -> ()
         | _ -> failwith "Internal inconsistency"
       in
       populate_stats (""::!subsets, true::ref_trust_flags);
     end
  | _ -> raise (InvalidNumberOfFields 17)



let write_one_line write_fun subset (at1, compat1, at2, compat2) count =
  write_fun [ subset; string_of_int at1; if compat1 then "1" else "0";
              string_of_int at2; if compat2 then "1" else "0"; string_of_int count ]

let write_one_subset write_fun subset subset_h =
  Hashtbl.iter (write_one_line write_fun subset) subset_h

let write_one_campaign ops campaign campaign_h =
  let table_name = "stats_answertype_comparison_" ^ (string_of_int !ref_campaign) ^ "_" ^ (string_of_int campaign) in
  let write_fun = ops.write_line table_name "" in  
  Hashtbl.iter (write_one_subset write_fun) campaign_h


let _ =
  let args = parse_args ~progname:"computeAnswerTypes" options Sys.argv in
  let campaigns_to_test = List.map int_of_string args in
  if !data_dir = "" then usage "computeAnswerTypes" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in

    let chain_sets = load_trusted_chains ops !subsets in
    if !verbose then print_endline "Trust info loaded.";
    let chain_validities =
      if !load_validity then begin
        let cv = load_chain_validities ops in
        if !verbose then print_endline "Validity info loaded.";
        cv
      end else Hashtbl.create 10
    in

    let ref_data = Hashtbl.create 10 in
    ops.iter_lines "answers" (compute_reference ref_data chain_sets chain_validities);
    if !verbose then print_endline "Reference computed.";

    let stats = Hashtbl.create 10 in
    let create_campaign_hash c =
      let subset_h = Hashtbl.create 10 in
      List.iter (fun s -> Hashtbl.replace subset_h s (Hashtbl.create 100)) (""::!subsets);
      Hashtbl.replace stats c subset_h
    in
    List.iter create_campaign_hash campaigns_to_test;
    ops.iter_lines "answers" (handle_answer ref_data stats campaigns_to_test);

    Hashtbl.iter (write_one_campaign ops) stats;

    ops.close_all_files ()
  with
    | e -> prerr_endline (Printexc.to_string e); exit 1
