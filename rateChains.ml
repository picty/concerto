(* rateChains.ml

   Inputs:
    - built_chains.csv
    - trusted_chains.csv

   Option:
    - trust_flag

   Outputs:
    - rated_chains.csv
 *)

open Parsifal
open Getopt
open FileOps
open X509Util

let data_dir = ref ""
let trust_flag = ref "trusted"

let options = [
  mkopt (Some 'h') "help" Usage "show this help";

  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 't') "trust-flag" (StringVal trust_flag) "specify the trust flag (trusted by default)";
]



let populate_chains chains = function
  | [chain_h; n; len_str; complete_str; n_ordered_str; n_transvalid_str; n_unused_str; _; _] ->
     let len = int_of_string len_str
     and complete = complete_str = "1"
     and n_ordered = int_of_string n_ordered_str
     and n_transvalid = int_of_string n_transvalid_str
     and n_unused = int_of_string n_unused_str in
     (* If only the root cert is external, we should not count it as transvalid *)
     let revised_n_transvalid = if (n_ordered = len - 1) && (n_transvalid = 1) && (n_unused = 0) then 0 else n_transvalid
     and ordered = n_ordered = len || (n_ordered = len - 1 && n_transvalid = 1) in
     Hashtbl.replace chains (chain_h, n) (complete, ordered, n_unused, revised_n_transvalid)
  | _ -> raise (InvalidNumberOfFields 9)

let populate_chain_trust trusted_chains = function
  | [chain_h; n; trust_mark] ->
     if trust_mark = !trust_flag then Hashtbl.replace trusted_chains (chain_h, n) ()
  | _ -> raise (InvalidNumberOfFields 3)


let rate_chain ops trusted_chains (chain_h, n) (complete, ordered, n_unused, n_transvalid) =
  let trusted = Hashtbl.mem trusted_chains (chain_h, n) in
  let grade = match complete, trusted, ordered, n_unused, n_transvalid with
    | true,  true,  true,  0, 0 -> "A"
    | true,  true,  true,  _, 0 -> "B"
    | true,  true,  false, _, 0 -> "C"
    | true,  true,  _,     _, _ -> "D"

    | true,  false, true,  0, 0 -> "C"
    | true,  false, true,  _, 0 -> "D"
    | true,  false, false, _, 0 -> "D"
    | true,  false, _,     _, _ -> "E"

    | false, _,     _,     _, _ -> "F"
  in
  ops.write_line "rated_chains" "" [chain_h; n; !trust_flag; grade]


let _ =
  (* TODO: Check that this _ is [] *)
  let _ = parse_args ~progname:"rateChains" options Sys.argv in
  try
    let ops = prepare_data_dir !data_dir in
    let chains = Hashtbl.create 1000
    and trusted_chains = Hashtbl.create 1000 in
    ops.iter_lines "built_chains" (populate_chains chains);
    ops.iter_lines "trusted_chains" (populate_chain_trust trusted_chains);
    Hashtbl.iter (rate_chain ops trusted_chains) chains;
    ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
