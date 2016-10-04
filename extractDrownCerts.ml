(* extractDrownCerts.ml

   Input:
   - answers.csv
   - chains.csv

   Output:
   - trusted-certs.csv
   - trusted-chains.csv
 *)

open Getopt
open FileOps
open ConcertoUtils

let verbose = ref false
let data_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
]


let handle_one_answer drown_chains = function
  | _::_::_::_::_::"20"::"2"::_::_::_::_::chain_hash::_ ->
     StringSet.add chain_hash drown_chains
  | _ -> drown_chains

let extract_certificates ops drown_chains drown_certs = function
  | [chain_hash; "0"; cert_hash] ->
     if StringSet.mem chain_hash drown_chains && ops.check_key_freshness "trusted_certs" cert_hash
     then begin
       ops.write_line "trusted_certs" cert_hash [cert_hash; "@drown"];
       StringSet.add cert_hash drown_certs;
     end else drown_certs
  | _ -> drown_certs

let mark_vulnerable_chains ops drown_certs = function
  | [chain_hash; "0"; cert_hash] ->
     if StringSet.mem cert_hash drown_certs
     then ops.write_line "trusted_chains" cert_hash [chain_hash; "@drown"]
  | _ -> ()
    

let _ =
  let _ = parse_args ~progname:"extractDrownCerts" options Sys.argv in
  if !data_dir = "" then usage "extractDrownCerts" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in

    let drown_chains = ops.iter_lines_accu "answers" handle_one_answer (StringSet.empty) in
    if !verbose then print_endline "DROWN chains identified.";
    let drown_certs = ops.iter_lines_accu "chains" (extract_certificates ops drown_chains) (StringSet.empty) in
    if !verbose then print_endline "DROWN certificates identified.";
    ops.iter_lines "chains" (mark_vulnerable_chains ops drown_certs);
    if !verbose then print_endline "Vulnerable chains marked.";

    ops.close_all_files ()
  with
    | e -> prerr_endline (Printexc.to_string e); exit 1

