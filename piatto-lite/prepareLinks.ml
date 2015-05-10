open Parsifal
open Getopt
open CsvOps

let verbose = ref false
let output_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'o') "output-dir" (StringVal output_dir) "set the output directory for dump2html or dump2csv";
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

let add_line l =
  match string_split ':' l with
  | cert_hash::_version::_serial::subject_hash::issuer_hash::_ ->
    let cert_hash = unquote cert_hash
    and issuer_hash = unquote issuer_hash
    and subject_hash = unquote subject_hash in
    Hashtbl.add issuer_hash_by_cert_hash cert_hash issuer_hash;
    Hashtbl.add cert_hash_by_subject_hash subject_hash cert_hash
  | _ -> ()

let read_csv csvname =
  let f = open_in csvname in
  let rec handle_line f =
    let line = try Some (input_line f) with End_of_file -> None in
    match line with
    | None -> ()
    | Some l ->
      add_line l;
      handle_line f
  in
  handle_line f

let write_possible_links ops cert_hash issuer_hash =
  let possible_issuers = Hashtbl.find_all cert_hash_by_subject_hash issuer_hash in
  let write_possible_issuer i = ops.write_line "possible_links" "" [cert_hash; i] in
  List.iter write_possible_issuer possible_issuers


let _ =
  let csv_files = parse_args ~progname:"prepareLinks" options Sys.argv in
  try
    let ops = prepare_csv_output_dir !output_dir in
    List.iter read_csv csv_files;
    Hashtbl.iter (write_possible_links ops) issuer_hash_by_cert_hash;
    ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
