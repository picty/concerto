open Parsifal

type csv_ops = {
  check_key_freshness : string -> string -> bool;
  close_all_files : unit -> unit;
  write_line : string -> string -> string list -> unit;
  dump_file : string -> string -> unit;
}

let try_mkdir dirname mode =
  try Unix.mkdir dirname mode
  with _ -> ()

let prepare_csv_output_dir output_dir =
  Unix.mkdir output_dir 0o755;
  Unix.mkdir (output_dir ^ "/raw") 0o755;
  let open_files = Hashtbl.create 10 in
  let open_file csv_name =
    try
      Hashtbl.find open_files csv_name
    with
      Not_found ->
	let f = open_out (output_dir ^ "/" ^ csv_name ^ ".csv") in
	let keys = Hashtbl.create 100 in
	Hashtbl.replace open_files csv_name (f, keys);
	f, keys
  in
  let check_key_freshness csv_name key =
    let _, keys = open_file csv_name in
    not (Hashtbl.mem keys key)
  and write_line csv_name key line =
    let f, keys = open_file csv_name in
    output_string f (String.concat ":" (List.map quote_string line));
    output_string f "\n";
    Hashtbl.replace keys key ()
  and close_all_files () =
    let close_file _ (f, _) = close_out f in
    Hashtbl.iter close_file open_files;
    Hashtbl.clear open_files
  and dump_file name content =
    let name_len = String.length name in
    let f =
      if name_len < 5
      then open_out (output_dir ^ "/raw/" ^ name)
      else begin
        let xx = String.sub name 0 2 in
        try_mkdir (output_dir ^ "/raw/" ^ xx) 0o755;
        open_out (output_dir ^ "/raw/" ^ xx ^ "/" ^ name)
      end
    in
    output_string f content;
    close_out f
  in
  { check_key_freshness; write_line;
    close_all_files; dump_file }


