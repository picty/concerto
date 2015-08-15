open Getopt
open FileOps

let data_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
]

let potentially_isolated = Hashtbl.create 1000
let not_isolated = Hashtbl.create 1000

let add_potentially_isolated ops h =
  if Hashtbl.mem not_isolated h
  then ops.write_line "real-links" "" [h; h]
  else Hashtbl.replace potentially_isolated h ()

let definitley_not_isolated ops h =
  if not (Hashtbl.mem not_isolated h) then begin
    if Hashtbl.mem potentially_isolated h then begin
      ops.write_line "real-links" "" [h; h];
      Hashtbl.remove potentially_isolated h
    end;
    Hashtbl.replace not_isolated h ()
  end


let handle_link ops = function
  | [subject_h; issuer_h] ->
    if subject_h <> issuer_h then begin
      ops.write_line "real-links" "" [subject_h; issuer_h];
      definitley_not_isolated ops subject_h;
      definitley_not_isolated ops issuer_h
    end else add_potentially_isolated ops subject_h
  | _ -> raise (InvalidNumberOfFields 2)


let _ =
  let csv_files = match parse_args ~progname:"checkLinks" options Sys.argv with
    | [] -> ["links"]
    | l -> l
  in
  try
    let ops = prepare_data_dir !data_dir in
    List.iter (fun csv -> ops.iter_lines csv (handle_link ops)) csv_files;
    let write_isolated_certs h _ = ops.write_line "isolated-links" "" [h; h] in
    Hashtbl.iter write_isolated_certs potentially_isolated;
    ops.close_all_files ()
  with e -> prerr_endline (Printexc.to_string e); exit 1
