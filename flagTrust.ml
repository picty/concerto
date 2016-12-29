(* flagTrust.ml

   Inputs:
    - built_links.csv
    - links.csv
    - chains.csv

   Argument:
    - trusted_certs

   Option:
    - trust_flag (the string as mark)

   Outputs:
    - trusted_certs.csv
    - trusted_chains.csv
    - trusted_built_chains.csv
 *)

open Parsifal
open Getopt
open FileOps

module StringSet = Set.Make(String)

module StringPair = struct
  type t = string * string
  let compare x y = Pervasives.compare x y
end
module StringPairSet = Set.Make(StringPair)

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


(* It seems that the subject lists associated to issuers can be very very long,
   leading to stack overflows. This is why we choose here a different
   structure from the simple Hashtbl in buildChains. *)
let read_links_by_issuer ops =
  let links = Hashtbl.create 1000 in
  let read_links_aux = function
    | [subject_h; issuer_h] ->
      let l =
        try Hashtbl.find links issuer_h
        with Not_found -> []
      in
      Hashtbl.replace links issuer_h (subject_h::l)
    | _ -> raise (InvalidNumberOfFields 2)
  in
  ops.iter_lines "links" read_links_aux;
  links

let extract_cert_hash cert_filename =
  let sc = X509Util.sc_of_input !base64 false (string_input_of_filename cert_filename) in
  hexdump (X509Util.hash_of_sc sc)

let update_trusted_built_chains trusted_roots trusted_built_chains = function
  | [chain_hash; chain_number; _; _; cert_hash] ->
     if (StringSet.mem cert_hash trusted_roots)
     then StringPairSet.add (chain_hash, chain_number) trusted_built_chains
     else trusted_built_chains
   | _ -> raise (InvalidNumberOfFields 5)

let rec update_trusted_certs trusted_certs links hashes =
  let update_aux h ((cur_hashes, cur_trusted_certs) as cur) =
    if StringSet.mem h cur_trusted_certs
    then cur
    else begin
      let next_trusted_certs = StringSet.add h cur_trusted_certs in
      let new_hashes =
        try Hashtbl.find links h
        with Not_found -> []
      in
      let next_hashes = List.fold_left (fun s e -> StringSet.add e s) cur_hashes new_hashes in
      next_hashes, next_trusted_certs
    end
  in
  let next_hashes, next_trusted_certs = StringSet.fold update_aux hashes (StringSet.empty, trusted_certs) in
  if StringSet.is_empty next_hashes
  then next_trusted_certs
  else update_trusted_certs next_trusted_certs links next_hashes

let update_trusted_chains trusted_certs trusted_chains = function
  | [chain_hash; "0"; cert_hash] ->
     if (StringSet.mem cert_hash trusted_certs)
     then StringSet.add chain_hash trusted_chains
     else trusted_chains
  | [_; _; _] -> trusted_chains
  | _ -> raise (InvalidNumberOfFields 3)

               
let _ =
  X509Util.relax_x509_constraints ();
  let trusted_root_certs = parse_args ~progname:"flagTrust" options Sys.argv in
  if !data_dir = "" then usage "flagTrust" options (Some "Please provide a valid data directory");
  if trusted_root_certs = [] then usage "flagTrust" options (Some "Please provide at least one certificate.");
  try
    let trusted_root_hashes = List.map extract_cert_hash trusted_root_certs in
    let trusted_roots = List.fold_left (fun s e -> StringSet.add e s) StringSet.empty trusted_root_hashes in
    let ops = prepare_data_dir !data_dir in
    if !verbose then print_endline "roots.csv computed.";
    StringSet.iter (fun h -> ops.write_line "roots" "" [h; !trust_flag]) trusted_roots;
    if !verbose then print_endline "roots.csv written.";

    let trusted_built_chains = ops.iter_lines_accu "built_links" (update_trusted_built_chains trusted_roots) StringPairSet.empty in
    if !verbose then print_endline "trusted_built_chains.csv computed.";
    StringPairSet.iter (fun (c, n) -> ops.write_line "trusted_built_chains" "" [c; n; !trust_flag]) trusted_built_chains;
    if !verbose then print_endline "trusted_built_chains.csv written.";

    let links = read_links_by_issuer ops in
    if !verbose then print_endline "Links loaded.";
    let trusted_certs = update_trusted_certs StringSet.empty links trusted_roots in
    if !verbose then print_endline "trusted_certs.csv computed.";
    StringSet.iter (fun h -> ops.write_line "trusted_certs" "" [h; !trust_flag]) trusted_certs;
    if !verbose then print_endline "trusted_certs.csv written.";

    let trusted_chains = ops.iter_lines_accu "chains" (update_trusted_chains trusted_certs) StringSet.empty in
    if !verbose then print_endline "trusted_chains.csv computed.";
    StringSet.iter (fun c -> ops.write_line "trusted_chains" "" [c; !trust_flag]) trusted_chains;
    if !verbose then print_endline "trusted_chains.csv written.";

    ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
