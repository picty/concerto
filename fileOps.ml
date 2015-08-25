open Parsifal



(* TODO
 - Rewrite a correct version of list (it might be in two parts: list-prefixes and list-prefix
 - Add support for rwlocks in file openings
 - Enforce R ^ W on bin files ?
 - Add an option to check whether a file exists before destroying it or appending it
   (sometimes we need to start from scratch, but might want to warn the user before
   truncating the file)
 - Add an option to check for unique keys, even when reopening a file ?
 - All these options + the possible rewrite tools (input and output files) can be added when creating file_ops
*)
type file_ops = {
  (* Read operations for CSV file *)
  iter_lines : string -> (string list -> unit) -> unit;
  iter_lines_accu : 'a. string -> ('a -> string list -> 'a) -> 'a -> 'a;

  (* Write operations for CSV file *)
  check_key_freshness : string -> string -> bool;
  write_line : string -> string -> string list -> unit;

  (* Read/Write operations for binary files *)
  read_file : string -> string -> string;
  dump_file : string -> string -> string -> unit;
  list_files : string -> string -> (string * int * int) list;
  
  close_all_files : unit -> unit;
}


let try_mkdir dirname mode =
  try Unix.mkdir dirname mode
  with _ -> ()

(* TODO: Write a proper unquote... This one is safe but restricted. *)
let unquote s =
  let s_len = String.length s in
  if s_len < 2 then failwith "unquote: invalid quoted string";
  if s.[0] <> '"' || s.[s_len - 1] <> '"' then failwith "unquote: string is not quoted";
  let result = String.sub s 1 (s_len - 2) in
  try ignore (String.index result '"'); failwith "unquote: too many quotes!"
  with Not_found -> result



exception InvalidNumberOfFields of int

let prepare_data_dir data_dir =
  try_mkdir data_dir 0o755;
  try_mkdir (data_dir ^ "/raw") 0o755;

  (* CSV helpers *)

  let open_wfiles = Hashtbl.create 10 in

  let open_wfile csv_name =
    try
      Hashtbl.find open_wfiles csv_name
    with
      Not_found ->
        (* TODO: Here we do not guarantee anymore the absence of dupes, as soon as we append! *)
	let f = open_out_gen [Open_wronly; Open_append; Open_creat] 0o644 (data_dir ^ "/" ^ csv_name ^ ".csv") in
	let keys = Hashtbl.create 100 in
	Hashtbl.replace open_wfiles csv_name (f, keys);
	f, keys
  in


  (* Binary files operations *)

  let open_binfiles = Hashtbl.create 10 in

  let rec read_existing_files f k =
    let b =
      try Some (input_byte f)
      with End_of_file -> None
    in
    match b with
    | Some b1 ->
      let b2 = input_byte f in
      let name_len = (b1 lsl 8) lor b2 in
      let name = String.make name_len ' ' in
      really_input f name 0 name_len;
      let b1 = input_byte f in
      let b2 = input_byte f in
      let b3 = input_byte f in
      let b4 = input_byte f in
      let offset = pos_in f in
      let contents_len = (b1 lsl 24) lor (b2 lsl 16) lor (b3 lsl 8) lor b4 in
      seek_in f ((pos_in f) + contents_len);
      Hashtbl.replace k name (offset, contents_len);
      read_existing_files f k
    | None -> ()
  in

  let open_binfile filetype name =
    let prefix = if String.length name < 2 then "_" else String.sub name 0 2 in
    try
      Hashtbl.find open_binfiles (filetype, prefix)
    with
      Not_found ->
        try_mkdir (data_dir ^ "/raw/" ^ filetype) 0o755;
        let wrfd = Unix.openfile
          (data_dir ^ "/raw/" ^ filetype ^ "/" ^ prefix ^ ".pack")
          [Unix.O_RDWR; Unix.O_CREAT] 0o644
        in
	let keys = Hashtbl.create 100 in

        let rdfd = Unix.dup wrfd in
        let in_f = Unix.in_channel_of_descr rdfd in
        read_existing_files in_f keys;

        let out_f = Unix.out_channel_of_descr wrfd in
        seek_out out_f (out_channel_length out_f);
	Hashtbl.replace open_binfiles (filetype, prefix) (in_f, out_f, keys);
	in_f, out_f, keys
  in


  (* CSV operations *)

  (* TODO: Factor the two following functions? *)
  let iter_lines csv_name line_handler =
    let f = open_in (data_dir ^ "/" ^ csv_name ^ ".csv") in
    let rec handle_line f =
      let line = try Some (input_line f) with End_of_file -> None in
      match line with
      | None -> close_in f
      | Some l ->
         try
           line_handler (List.map unquote (string_split ':' l));
           handle_line f
         with
         | InvalidNumberOfFields n ->
            close_in f;
            failwith ("Invalid number of fields (" ^ (string_of_int n) ^ " expected) in " ^ (quote_string l))
         | e ->
            close_in f;
            raise e
    in
    handle_line f

  and iter_lines_accu csv_name line_handler initial_accu =
    let f = open_in (data_dir ^ "/" ^ csv_name ^ ".csv") in
    let rec handle_line accu f =
      let line = try Some (input_line f) with End_of_file -> None in
      match line with
      | None -> close_in f; accu
      | Some l ->
         try
           let new_accu = line_handler accu (List.map unquote (string_split ':' l)) in
           handle_line new_accu f
         with
         | InvalidNumberOfFields n ->
            close_in f;
            failwith ("Invalid number of fields (" ^ (string_of_int n) ^ " expected) in " ^ (quote_string l))
         | e ->
            close_in f;
            raise e
    in
    handle_line initial_accu f

  and check_key_freshness csv_name key =
    let _, keys = open_wfile csv_name in
    not (Hashtbl.mem keys key)
  and write_line csv_name key line =
    let f, keys = open_wfile csv_name in
    output_string f (String.concat ":" (List.map quote_string line));
    output_string f "\n";
    Hashtbl.replace keys key ()

  and list_files filetype name =
    let _, _, keys = open_binfile filetype name in
    let inner_fun name (offset, len) accu = (name, offset, len)::accu in
    Hashtbl.fold inner_fun keys []
  and read_file filetype name =
    let f, _, keys = open_binfile filetype name in
    let offset, len = Hashtbl.find keys name in
    seek_in f offset;
    let result = String.make len ' ' in
    really_input f result 0 len;
    result
  and dump_file filetype name contents =
    let _, f, keys = open_binfile filetype name in
    if not (Hashtbl.mem keys name) then begin
      let name_len = String.length name
      and contents_len = String.length contents in
      (*      seek_out f (out_channel_length f); *) (* TODO: This does *NOT* work. *)
      output_byte f ((name_len lsr 8) land 255);
      output_byte f (name_len land 255);
      output_string f name;
      let offset = pos_out f in
      output_byte f ((contents_len lsr 24) land 255);
      output_byte f ((contents_len lsr 16) land 255);
      output_byte f ((contents_len lsr 8) land 255);
      output_byte f (contents_len land 255);
      output_string f contents;
      Hashtbl.replace keys name (offset, contents_len);
    end

  and close_all_files () =
    let close_file _ (f, _) = close_out f in
    let close_binfile _ (in_f, out_f, _) =
      close_in in_f;
      close_out out_f
    in
    Hashtbl.iter close_file open_wfiles;
    Hashtbl.clear open_wfiles;
    Hashtbl.iter close_binfile open_binfiles;
    Hashtbl.clear open_binfiles

  in
  { iter_lines; iter_lines_accu;
    check_key_freshness; write_line;
    read_file; dump_file; list_files;
    close_all_files; }
