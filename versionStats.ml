(* versionStats.ml

   Inputs:
    - answers.csv

   Option:
    - campaign id
    - trust_flag filters
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


let update_count chain_sets counts = function
  | [campaign_str; _; _; _; _; ("20"|"21"); version_str; _; _; _; chain_hash] ->
     let campaign = int_of_string campaign_str
     and version = int_of_string version_str in

     let campaign_total_h, campaign_by_filter_h =
       try Hashtbl.find counts campaign
       with Not_found ->
         let h1 = Hashtbl.create 1000
         and h2 = Hashtbl.create 10 in
         List.iter (fun trust_flag -> Hashtbl.add h2 trust_flag (Hashtbl.create 1000)) !filters;
         Hashtbl.replace counts campaign (h1, h2);
         h1, h2
     in

     inc_in_hashtbl campaign_total_h version;
     let increment_for_flag trust_flag =
       if is_flagged_with chain_sets trust_flag chain_hash
       then inc_in_hashtbl (Hashtbl.find campaign_by_filter_h trust_flag) version
     in
     List.iter increment_for_flag !filters

  | [_ ; _; _; _; _; _; _; _; _; _; _] -> ()

  | _ -> raise (InvalidNumberOfFields 11)


let print_one_hashtbl name h =
  print_endline ("== " ^ name ^ " ==");
  let total = Hashtbl.fold (fun _ n accu -> accu+n) h 0 in
  Printf.printf "Total: %10d\n" total;
  Hashtbl.iter (fun t c ->  Printf.printf "%5d: %10d\n" t c) h;
  print_newline ()

let print_counts_for_one_campaign campaign (total_h, filtered_h) =
  Printf.printf "= %d =\n\n" campaign;
  print_one_hashtbl "All" total_h;
  Hashtbl.iter print_one_hashtbl filtered_h;
  print_newline ()


let _ =
  let _ = parse_args ~progname:"versionStats" options Sys.argv in
  if !data_dir = "" then usage "versionStats" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in

    let chain_sets = load_trusted_chains ops !filters in
    if !verbose then print_endline "Trust info loaded.";

    let counts = Hashtbl.create 10 in
    ops.iter_lines "answers" (update_count chain_sets counts);
    Hashtbl.iter print_counts_for_one_campaign counts;

    ops.close_all_files ()
  with
    | e -> prerr_endline (Printexc.to_string e); exit 1
