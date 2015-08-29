(* prepareLinks.ml

   Inputs:
    - certs.csv (or other csv files specified as args)

   Outputs:
    - possible_links.csv
 *)

open Parsifal
open Getopt
open FileOps

let rundry = ref false
let accept_v1_ca = ref false
let data_dir = ref ""

let multiple = ref 1

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'n') "run-dry" (Set rundry) "do not produce links.csv, just count the lines";
  mkopt (Some '1') "accept-version1-ca" (Set accept_v1_ca) "accept X.509v1 certificates as CA";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 'M') "multiple" (IntVal multiple) "set the number of output for possible links."
]


let issuer_hash_by_cert_hash = Hashtbl.create 1000
let cert_hash_by_subject_hash = Hashtbl.create 1000

let is_ca version isCA = isCA = "1" || (version = "1" && !accept_v1_ca)

let add_line = function
  | cert_hash::version::serial::subject_hash::issuer_hash::
      _not_before::_not_after::_key_type::_rsa_modulus::_rsa_exponent::isCA::ski::aki_ki::aki_serial::_ ->
    Hashtbl.add issuer_hash_by_cert_hash cert_hash (issuer_hash, aki_ki, aki_serial);
    if is_ca version isCA then Hashtbl.add cert_hash_by_subject_hash subject_hash (cert_hash, ski, serial)
  | _ -> ()

let filter_fun aki_ki aki_serial (_, ski, serial) = (aki_ki = "" || aki_ki = ski) && (aki_serial = "" || aki_serial = serial)


let get_filename n_ref max =
  if max < 2
  then "possible_links"
  else begin
    let res = "possible_links_" ^ (string_of_int !n_ref) in
    incr n_ref;
    if !n_ref >= max then n_ref := 0;
    res
  end

let write_possible_links ops n cert_hash (issuer_hash, aki_ki, aki_serial) =
  let possible_issuers = Hashtbl.find_all cert_hash_by_subject_hash issuer_hash in
  let write_possible_issuer (i, _, _) = ops.write_line (get_filename n !multiple) "" [cert_hash; i] in
  List.iter write_possible_issuer (List.filter (filter_fun aki_ki aki_serial) possible_issuers)

let count_possible_links total _cert_hash (issuer_hash, aki_ki, aki_serial) (n_certs, n_links) =
  let possible_issuers = Hashtbl.find_all cert_hash_by_subject_hash issuer_hash in
  let new_n_certs = n_certs + 1
  and new_n_links = n_links + (List.length (List.filter (filter_fun aki_ki aki_serial) possible_issuers)) in
  if (new_n_certs mod 1000) = 0 then begin
    let average_links = float new_n_links /. float new_n_certs in
    let estimated_links = float total *. average_links in
    Printf.printf "%d/%d certs, %d links, est. %.2f total links\n" new_n_certs total new_n_links estimated_links
  end;
  new_n_certs, new_n_links

let _ =
  let csv_files = match parse_args ~progname:"prepareLinks" options Sys.argv with
    | [] -> ["certs"]
    | l -> l
  in
  if !data_dir = "" then usage "prepareLinks" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in
    List.iter (fun csv -> ops.iter_lines csv add_line) csv_files;
    if not !rundry then begin
      let n = ref 0 in
      Hashtbl.iter (write_possible_links ops n) issuer_hash_by_cert_hash;
      ops.close_all_files ()
    end else begin
      let total = Hashtbl.length issuer_hash_by_cert_hash in
      let _, res = Hashtbl.fold (count_possible_links total) issuer_hash_by_cert_hash (0, 0) in
      Printf.printf "%d certs, %d links\n" total res
    end
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
