open Parsifal
open Getopt
open FileOps
open X509Util

let verbose = ref false
let output_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'o') "output-dir" (StringVal output_dir) "set the output directory (isolated certs + real links)";
]

let potentially_isolated = Hashtbl.create 1000
let not_isolated = Hashtbl.create 1000

let add_potentially_isolated out_ops h =
  if Hashtbl.mem not_isolated h
  then out_ops.write_line "real-links" "" [h; h]
  else Hashtbl.replace potentially_isolated h ()

let definitley_not_isolated out_ops h =
  if not (Hashtbl.mem not_isolated h) then begin
    if Hashtbl.mem potentially_isolated h then begin
      out_ops.write_line "real-links" "" [h; h];
      Hashtbl.remove potentially_isolated h
    end;
    Hashtbl.replace not_isolated h ()
  end

  
let read_csv out_ops csvname =
  let f = open_in csvname in
  let rec handle_line f =
    let line = try Some (input_line f) with End_of_file -> None in
    match line with
    | None -> close_in f
    | Some l ->
      match List.map unquote (string_split ':' l) with
      | [subject_h; issuer_h] ->
        if subject_h <> issuer_h then begin
          out_ops.write_line "real-links" "" [subject_h; issuer_h];
          definitley_not_isolated out_ops subject_h;
          definitley_not_isolated out_ops issuer_h
        end else add_potentially_isolated out_ops subject_h;
        handle_line f
      | _ -> failwith ("Invalid line (" ^ (quote_string l) ^ ")")
  in
  handle_line f


let _ =
  let csv_files = parse_args ~progname:"checkLinks" options Sys.argv in
  try
    let out_ops = prepare_csv_output_dir !output_dir in
    List.iter (read_csv out_ops) csv_files;
    let write_isolated_certs h _ = out_ops.write_line "isolated-links" "" [h; h] in
    Hashtbl.iter write_isolated_certs potentially_isolated;
    out_ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
