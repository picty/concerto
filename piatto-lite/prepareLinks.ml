open Parsifal
open Getopt
open FileOps

let verbose = ref false
let rundry = ref false
let accept_v1_ca = ref false
let output_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'n') "run-dry" (Set rundry) "do not produce links.csv, just count the lines";
  mkopt (Some '1') "accept-version1-ca" (Set accept_v1_ca) "accept X.509v1 certificates as CA";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'o') "output-dir" (StringVal output_dir) "set the output directory";
]


let issuer_hash_by_cert_hash = Hashtbl.create 1000
let cert_hash_by_subject_hash = Hashtbl.create 1000

let unquote s =
  let s_len = String.length s in
  if s_len < 2 then failwith "unquote: invalid quoted string";
  if s.[0] <> '"' || s.[s_len - 1] <> '"' then failwith "unquote: string is not quoted";
  let result = String.sub s 1 (s_len - 2) in
  try ignore (String.index result '"'); failwith "unquote: too many quotes!"
  with Not_found -> result

let is_ca version isCA = isCA = "\"1\"" || (version = "\"1\"" && !accept_v1_ca)

let add_line l =
  match string_split ':' l with
  | cert_hash::version::_serial::subject_hash::issuer_hash::
      _not_before::_not_after::_key_type::_rsa_modulus::_rsa_exponent::isCA::_ ->
    let cert_hash = unquote cert_hash
    and issuer_hash = unquote issuer_hash
    and subject_hash = unquote subject_hash in
    Hashtbl.add issuer_hash_by_cert_hash cert_hash issuer_hash;
    if is_ca version isCA then Hashtbl.add cert_hash_by_subject_hash subject_hash cert_hash
  | _ -> ()

let read_csv csvname =
  let f = open_in csvname in
  let rec handle_line f =
    let line = try Some (input_line f) with End_of_file -> None in
    match line with
    | None -> close_in f
    | Some l ->
      add_line l;
      handle_line f
  in
  handle_line f

let write_possible_links ops cert_hash issuer_hash =
  let possible_issuers = Hashtbl.find_all cert_hash_by_subject_hash issuer_hash in
  let write_possible_issuer i = ops.write_line "possible_links" "" [cert_hash; i] in
  List.iter write_possible_issuer possible_issuers

let count_possible_links total _cert_hash issuer_hash (n_certs, n_links) =
  let possible_issuers = Hashtbl.find_all cert_hash_by_subject_hash issuer_hash in
  let new_n_certs = n_certs + 1
  and new_n_links = n_links + (List.length possible_issuers) in
  if (new_n_certs mod 1000) = 0 then begin
    let average_links = float new_n_links /. float new_n_certs in
    let estimated_links = float total *. average_links in
    Printf.printf "%d/%d certs, %d links, est. %.2f total links\n" new_n_certs total new_n_links estimated_links
  end;
  new_n_certs, new_n_links

let _ =
  let csv_files = parse_args ~progname:"prepareLinks" options Sys.argv in
  try
    List.iter read_csv csv_files;
    if not !rundry then begin
      let ops = prepare_csv_output_dir !output_dir in
      Hashtbl.iter (write_possible_links ops) issuer_hash_by_cert_hash;
      ops.close_all_files ()
    end else begin
      let total = Hashtbl.length issuer_hash_by_cert_hash in
      let _, res = Hashtbl.fold (count_possible_links total) issuer_hash_by_cert_hash (0, 0) in
      Printf.printf "%d certs, %d links\n" total res
    end
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
