(* filterDataDir.ml

   TODO

 *)

open Parsifal
open Getopt
open ConcertoUtils
open FileOps


let verbose = ref false
let in_data_dir = ref ""
let out_data_dir = ref ""
let selected_ips = Hashtbl.create 100
let selected_chain_hashes = Hashtbl.create 100
let selected_https_names = ref []
let selected_trust_flag = ref []

let load_strings h filename =
  let f = open_in filename in
  try
    while true do
      let line = input_line f in
      Hashtbl.add h line ()
    done;
    ActionDone
  with End_of_file -> ActionDone

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'd') "data-dir" (StringVal out_data_dir) "set the data directory";
  mkopt (Some 'i') "in-data-dir" (StringVal in_data_dir) "set the source data directory";

  mkopt None "filter-by-ip" (StringFun (load_strings selected_ips)) "filter using a list of ips";
  mkopt None "filter-by-chain-hash" (StringFun (load_strings selected_chain_hashes)) "filter using a list of ips";
  mkopt None "filter-by-https-name" (StringList selected_https_names) "filter using a regexp in certificate server names (CN or SAN)"; (* TODO: Choose which type? *)
  mkopt None "filter-by-trust-flag" (StringList selected_trust_flag) "filter using a trust flag";

  (* TODO: filter-by-hostname *)
]


let filter_by_ip ip_h = function
  | _::ip_str::_ -> Hashtbl.mem ip_h ip_str
  | _ -> false

let filter_by_chain_hash chains_h = function
  | _::_::_::_::_::_::_::_::_::_::_::chain_hash::_ -> Hashtbl.mem chains_h chain_hash
  | _ -> false

let add_chains_from_name_regex chains_to_populate in_ops re =
  let regex = Str.regexp re in
  let filter_names accu = function
    | h::_::n::_ ->
       if Str.string_match regex n 0
       then begin print_endline n; StringSet.add h accu; end
       else accu
    | _ -> accu
  in
  let selected_certs = in_ops.iter_lines_accu "names" filter_names StringSet.empty in
  let filter_chains = function
    | h::"0"::cert_hash::_ ->
       if StringSet.mem cert_hash selected_certs
       then Hashtbl.add chains_to_populate h ()
    | _ -> ()
  in
  in_ops.iter_lines "chains" filter_chains

let add_trusted_chains chains_to_populate in_ops trust_flag =
  let filter_chains = function
    | h::t::_ ->
       if t = trust_flag
       then Hashtbl.add chains_to_populate h ()
    | _ -> ()
  in
  in_ops.iter_lines "trusted_chains" filter_chains


let handle_answers out_ops filter_fun chains a =
  if filter_fun a then begin
    match a with
    | _::_::_::_::_::_::_::_::_::_::_::chain_hash::_ ->
       out_ops.write_line "answers" "" a;
       StringSet.add chain_hash chains
    | _ -> chains
  end else chains

let handle_chains out_ops chains certs = function
  | (chain_hash::_::cert_hash::_) as l ->
     if StringSet.mem chain_hash chains
     then begin
       out_ops.write_line "chains" "" l;
       StringSet.add cert_hash certs
     end else certs
  | _ -> certs

let add_root certs = function
  | cert_hash::_ -> StringSet.add cert_hash certs
  | _ -> certs

let handle_certs out_ops certs dns = function
  | (cert_hash::_::_::subject_hash::issuer_hash::_) as l ->
     if StringSet.mem cert_hash certs
     then begin
       out_ops.write_line "certs" "" l;
       StringSet.add issuer_hash (StringSet.add subject_hash dns)
     end else dns
  | _ -> dns

let handle_links write_fun certs = function
  | (subject_hash::issuer_hash::_) as l ->
     if StringSet.mem subject_hash certs || StringSet.mem issuer_hash certs
     then write_fun l
  | _ -> ()

let handle_simple_file write_fun keys = function
  | (key::_) as l ->
     if StringSet.mem key keys
     then write_fun l
  | _ -> ()

     
let _ =
  (* TODO: Check that _ is [] *)
  let _ = parse_args ~progname:"filterDataDir" options Sys.argv in
  if !out_data_dir = "" then usage "filterDataDir" options (Some "Please provide a valid data directory");
  if !in_data_dir = "" then usage "filterDataDir" options (Some "Please provide a valid source data directory");
  try
    let in_ops = prepare_data_dir !in_data_dir
    and out_ops = prepare_data_dir !out_data_dir in

    List.iter (add_chains_from_name_regex selected_chain_hashes in_ops) !selected_https_names;
    List.iter (add_trusted_chains selected_chain_hashes in_ops) !selected_trust_flag;
    let filter_fun = match Hashtbl.length selected_ips, Hashtbl.length selected_chain_hashes with
      | 0, 0 -> usage "filterDataDir" options (Some "Please provide a valid filter strategy with a non-empty list");
      | _, 0 -> filter_by_ip selected_ips
      | 0, _ -> filter_by_chain_hash selected_chain_hashes
      | _, _ -> (fun a -> filter_by_ip selected_ips a || filter_by_chain_hash selected_chain_hashes a)
    in
    if !verbose then prerr_endline "Filters prepared";

    let filtered_chains = in_ops.iter_lines_accu "answers" (handle_answers out_ops filter_fun) StringSet.empty in
    if !verbose then prerr_endline "Chains filtered";

    let filtered_certs =
      in_ops.iter_lines_accu "roots" add_root (in_ops.iter_lines_accu "chains" (handle_chains out_ops filtered_chains) StringSet.empty)
    in
    if !verbose then prerr_endline "Certificates filtered";

    let filtered_dns = in_ops.iter_lines_accu "certs" (handle_certs out_ops filtered_certs) StringSet.empty in
    if !verbose then prerr_endline "DNs filtered";

    let save_cert h = out_ops.dump_file "certs" h (in_ops.read_file "certs" h) in
    StringSet.iter save_cert filtered_certs;
    if !verbose then prerr_endline "Raw certificates copied";
    
    in_ops.iter_lines "links" (handle_links (out_ops.write_line "links" "") filtered_certs);
    (* TODO: transitive_links? *)

    let filter_file csv_name keys =
      in_ops.iter_lines csv_name (handle_simple_file (out_ops.write_line csv_name "") keys)
    in
    filter_file "names" filtered_certs;
    filter_file "unparsed_certs" filtered_certs;
    filter_file "trusted_certs" filtered_certs;

    filter_file "dns" filtered_dns;

    filter_file "built_chains" filtered_chains;
    filter_file "built_links" filtered_chains;
    filter_file "unused_certs" filtered_chains;
    filter_file "trusted_chains" filtered_chains;
    filter_file "trusted_built_chains" filtered_chains;
    filter_file "rated_chains" filtered_chains;
    
    let clone_file csv_name =
      try
        in_ops.iter_lines csv_name (out_ops.write_line csv_name "")
      with _ -> ()
    in
    List.iter clone_file ["campaigns"; "stimuli"; "stimuli_compressions";
                          "stimuli_suites"; "stimuli_versions"; "roots"; "v1cas"];

    in_ops.close_all_files ();
    out_ops.close_all_files ()
  with
    | ParsingException (e, h) -> 
      let current_prog = String.concat " " (Array.to_list Sys.argv) in
      prerr_endline ("[" ^ current_prog ^ "] " ^ (string_of_exception e h)); exit 1
    | e ->
      let current_prog = String.concat " " (Array.to_list Sys.argv) in
      prerr_endline ("[" ^ current_prog ^ "] " ^ (Printexc.to_string e)); exit 1
