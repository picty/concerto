(* flagTrust.ml

   Inputs:
    - links.csv
    - built_links.csv

   Argument:
    - trusted_certs

   Option:
    - trust_flag (the string as mark)

   Outputs:
    - trusted_certs.csv
    - trusted_chains.csv
 *)

open Parsifal
open Getopt
open FileOps
open X509Util

let verbose = ref false
let data_dir = ref ""
let trust_flag = ref "trusted"
let base64 = ref true

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt None "pem" (Set base64) "use PEM format (default)";
  mkopt None "der" (Clear base64) "use DER format";

  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 't') "trust-flag" (StringVal trust_flag) "specify the trust flag (trusted by default)";
]


let read_links ops =
  let links = Hashtbl.create 1000 in
  let read_links_aux = function
    | [subject_h; issuer_h] -> Hashtbl.add links issuer_h subject_h
    | _ -> raise (InvalidNumberOfFields 2)
  in
  ops.iter_lines "links" read_links_aux;
  links

let extract_cert_hash cert_filename =
  let sc = sc_of_input !base64 false (string_input_of_filename cert_filename) in
  hexdump (hash_of_sc sc)

let rec update_trusted_certs trusted_certs links hashes =
  let update_aux next_hashes h =
    if Hashtbl.mem trusted_certs h
    then next_hashes
    else begin
      Hashtbl.replace trusted_certs h ();
      List.rev_append (Hashtbl.find_all links h) next_hashes
    end
  in
  let next_hashes = List.fold_left update_aux [] hashes in
  if next_hashes <> [] then update_trusted_certs trusted_certs links next_hashes

let update_trusted_chains trusted_certs trusted_chains = function
  | [chain_hash; chain_number; _; _; cert_hash] ->
     if not (Hashtbl.mem trusted_chains (chain_hash, chain_number)) &&
          (Hashtbl.mem trusted_certs cert_hash)
     then Hashtbl.replace trusted_chains (chain_hash, chain_number) ()
  | _ -> raise (InvalidNumberOfFields 5)

let _ =
  let certs = parse_args ~progname:"flagTrust" options Sys.argv in
  if certs = [] then usage "flagTrust" options (Some "Please provide at least one certificate.");
  try
    let cert_hashes = List.map extract_cert_hash certs in
    let ops = prepare_data_dir !data_dir in
    let links = read_links ops in
    if !verbose then print_endline "Links loaded.";

    let trusted_certs = Hashtbl.create 1000 in
    update_trusted_certs trusted_certs links cert_hashes;
    Hashtbl.iter (fun h _ -> ops.write_line "trusted_certs" "" [h; !trust_flag]) trusted_certs;

    let trusted_chains = Hashtbl.create 1000 in
    ops.iter_lines "built_links" (update_trusted_chains trusted_certs trusted_chains);
    Hashtbl.iter (fun (c, n) _ -> ops.write_line "trusted_chains" "" [c; n; !trust_flag]) trusted_chains;

    ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
