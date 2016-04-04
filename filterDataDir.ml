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
let filter_ip_hash = ref None

let load_filter_ips_from_file filename =
  let h = match !filter_ip_hash with
    | None ->
       let table = Hashtbl.create 100 in
       filter_ip_hash := Some table;
       table
    | Some table -> table
  in
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

  mkopt None "filter-by-ip" (StringFun load_filter_ips_from_file) "filter using a list of ips";
(* TODO: filter-by-chain" *)
(* TODO: filter-by-trust-flag *)
(* TODO: filter-by-name" *)
]

let filter_by_ip ip_h = function
  | (_::ip_str::_) -> Hashtbl.mem ip_h ip_str
  | _ -> false

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

    let filter_fun = match !filter_ip_hash with
      | None -> usage "filterDataDir" options (Some "Please provide a valid filter strategy (or simply use cp?)");
      | Some h -> filter_by_ip h
    in

    let filtered_chains = in_ops.iter_lines_accu "answers" (handle_answers out_ops filter_fun) StringSet.empty in
    let filtered_certs =
      in_ops.iter_lines_accu "roots" add_root (in_ops.iter_lines_accu "chains" (handle_chains out_ops filtered_chains) StringSet.empty)
    in
    let filtered_dns = in_ops.iter_lines_accu "certs" (handle_certs out_ops filtered_certs) StringSet.empty in

    let save_cert h = out_ops.dump_file "certs" h (in_ops.read_file "certs" h) in
    StringSet.iter save_cert filtered_certs;
    
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
