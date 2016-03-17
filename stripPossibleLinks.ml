(* stripPossibleLinks.ml

   Inputs:
    - possible_links.csv

   Outputs:
    - stripped_possible_links.csv
 *)

open Parsifal
open Getopt
open FileOps

let data_dir = ref ""

type state = Crunching | SkippingUntil of string * string

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
]


let strip_one_line ops accu line = match accu, line with
  | SkippingUntil (s, i), [subject_h; issuer_h] ->
     if s = subject_h && i = issuer_h then Crunching else accu
  | Crunching, [subject_h; issuer_h] ->
     ops.write_line "stripped_possible_links" "" [subject_h; issuer_h];
     Crunching
  | _ -> raise (InvalidNumberOfFields 2)


let _ =
  let initial_state = match parse_args ~progname:"stripPossibleLinks" options Sys.argv with
    | [s; i] -> SkippingUntil (s, i)
    | _ -> usage "stripPossibleLinks" options (Some "Please provide two cert hashes");
  in
  if !data_dir = "" then usage "stripPossibleLinks" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in
    begin
      match ops.iter_lines_accu "possible_links" (strip_one_line ops) initial_state with
      | Crunching -> ()
      | SkippingUntil _ -> prerr_endline "Line not found..."
    end;
    ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
