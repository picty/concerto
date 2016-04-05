(* TODO
 - Add load/build_index functions for binary files
 - Add an option to check whether a file exists before destroying it or appending it
   (sometimes we need to start from scratch, but might want to warn the user before
   truncating the file)
 - Add an option to check for unique keys for some CSV (dns, chains on merge), even when reopening a file ?
 - All these options + the possible rewrite tools (input and output files) can be added when creating file_ops
*)
type file_ops = {
  (* Read operations for CSV file *)
  list_csv_files : unit -> string list;
  iter_lines : string -> (string list -> unit) -> unit;
  iter_lines_accu : 'a. string -> ('a -> string list -> 'a) -> 'a -> 'a;

  (* Write operations for CSV file *)
  reload_keys : string -> (string list -> string) -> unit;
  check_key_freshness : string -> string -> bool;
  write_line : string -> string -> string list -> unit;

  (* Read/Write operations for binary files *)
  list_filetypes : unit -> string list;
  list_prefixes : string -> string list;
  list_files_by_prefix : string -> string -> (string * int * int) list;
  read_file : string -> string -> string;
  dump_file : string -> string -> string -> unit;

  close_all_files : unit -> unit;
}


let try_mkdir dirname mode =
  try Unix.mkdir dirname mode
  with _ -> ()


(* The following functions (quote/unquote) are hackish, since sqlite
   does not seem to handle properly binary entries, and uses "" to
   escape quotes. *)

let quote_csv_field s =
  let n = String.length s in
  let res = Buffer.create (2 * n) in

  let mk_two_char c =
    Buffer.add_char res '\\';
    Buffer.add_char res c
  in
  let write_char c =
    match c with
      | '\n' -> mk_two_char 'n'
      | '\t' -> mk_two_char 't'
      | '\\' -> mk_two_char '\\'
      | '"' -> Buffer.add_char res '"'; Buffer.add_char res '"'
      | c ->
	let x = int_of_char c in
	if x >= 32 && x < 128
	then Buffer.add_char res c
	else begin
	  mk_two_char 'x';
	  Buffer.add_char res Parsifal.hexa_char.[x lsr 4];
	  Buffer.add_char res Parsifal.hexa_char.[x land 15]
	end
  in
  Buffer.add_char res '"';
  for i = 0 to (n-1) do
    write_char s.[i]
  done;
  Buffer.add_char res '"';
  Buffer.contents res

let quote_csv_line line =
  String.concat ":" (List.map quote_csv_field line)


let unquote_csv_line l =
  let s_len = String.length l in

  let rec expecting_opening_quotes fields i =
    if i >= s_len
    then failwith "csv_unquote: unexpected colon at the end of line"
    else if l.[i] != '"'
    then failwith "csv_unquote: expected quote after colon"
    else inside_quote fields (Buffer.create 10) (i+1)
  and inside_quote fields buf i =
    if i >= s_len
    then failwith "csv_unquote: missing final quote"
    else match l.[i] with
      | '"' ->
        if (i < s_len - 1) && (l.[i+1] = '"')
        then begin
          Buffer.add_char buf '"';
          inside_quote fields buf (i+2)
        end
        else expecting_colon_or_eol ((Buffer.contents buf)::fields) (i+1)
      | '\\' ->
        if i < s_len + 2 then begin
          let next_i = match l.[i+1] with
            | 'n' -> Buffer.add_char buf '\n'; i+2
            | 't' -> Buffer.add_char buf '\t'; i+2
            | '\\' -> Buffer.add_char buf '\\'; i+2
            | 'x' ->
              if i < s_len + 4 then begin
                match Parsifal.reverse_hex_chars.(int_of_char l.[i+2]),
                      Parsifal.reverse_hex_chars.(int_of_char l.[i+3]) with
                | -1, _ | _, -1 -> failwith "csv_unquote: invalid hex char"
                | a, b -> Buffer.add_char buf (char_of_int ((a lsl 4) lor b)); i+4
              end else failwith "csv_unquote: unexpected end of line"
            | _ -> failwith "csv_unquote: invalid char escape"
          in inside_quote fields buf next_i
        end else failwith "csv_unquote: unexpected end of line"
      | c ->
        let x = int_of_char c in
        if x >= 32 && x < 128
        then Buffer.add_char buf c
        else failwith "csv_unquote: invalid non-ASCII character";
        inside_quote fields buf (i+1)
  and expecting_colon_or_eol fields i =
    if i >= s_len
    then List.rev fields
    else if l.[i] != ':'
    then failwith "csv_unquote: expected colon or end of line"
    else expecting_opening_quotes fields (i+1)
  in

  expecting_opening_quotes [] 0


let list_dir filter_funs dirname =
  let dirfd = Unix.opendir dirname in
  let rec list_dir_aux accu =
    let next_entry =
      try Some (Unix.readdir dirfd)
      with End_of_file -> Unix.closedir dirfd; None
    in
    let apply_filters filters x =
      let results = List.map (fun f -> f (dirname, x)) filters in
      List.fold_left (&&) true results
    in
    match next_entry with
    | Some e ->
       if apply_filters filter_funs e
       then list_dir_aux (e::accu)
       else list_dir_aux accu
    | None -> List.rev accu
  in
  list_dir_aux []

let check_file_kind k (dirname, basename) =
  let stats = Unix.stat (dirname ^ "/" ^ basename) in
  stats.Unix.st_kind = k

let check_extension ext (_, basename) =
  let f_len = String.length basename
  and e_len = String.length ext in
  if f_len > e_len
  then String.sub basename (f_len - e_len) e_len = ext
  else false

let remove_extension ext basename =
  let f_len = String.length basename
  and e_len = String.length ext in
  if f_len > e_len && String.sub basename (f_len - e_len) e_len = ext
  then String.sub basename 0 (f_len - e_len)
  else basename

let remove_hidden_files (_, basename) =
  String.length basename > 1 && basename.[0] <> '.'


exception InvalidNumberOfFields of int

let prepare_data_dir data_dir =
  try_mkdir data_dir 0o755;
  try_mkdir (data_dir ^ "/raw") 0o755;

  (* CSV helpers *)

  let open_wfiles = Hashtbl.create 10 in

  let open_rfile csv_name =
    let fd = Unix.openfile (data_dir ^ "/" ^ csv_name ^ ".csv") [Unix.O_RDONLY; Unix.O_CREAT] 0o644 in
    Unix.lockf fd Unix.F_RLOCK 0;
    Unix.in_channel_of_descr fd
  in

  let open_wfile csv_name =
    try
      Hashtbl.find open_wfiles csv_name
    with
      Not_found ->
        (* TODO: Here we do not guarantee anymore the absence of dupes, as soon as we append! *)
        let wrfd = Unix.openfile (data_dir ^ "/" ^ csv_name ^ ".csv") [Unix.O_RDWR; Unix.O_APPEND; Unix.O_CREAT] 0o644 in
        Unix.lockf wrfd Unix.F_LOCK 0;
        let rdfd = Unix.dup wrfd in
        let in_f = Unix.in_channel_of_descr rdfd in
        let out_f = Unix.out_channel_of_descr wrfd in
        let keys = Hashtbl.create 100 in
        Hashtbl.replace open_wfiles csv_name (in_f, out_f, keys);
        in_f, out_f, keys
  in

  let rec iter_lines_aux accu line_handler f =
    let line = try Some (input_line f) with End_of_file -> None in
    match line with
    | None -> close_in f; accu
    | Some "" -> iter_lines_aux accu line_handler f
    | Some l ->
       let new_accu =
         try
           line_handler accu (unquote_csv_line l)
         with
         | InvalidNumberOfFields n ->
            close_in f;
            failwith ("Invalid number of fields (" ^ (string_of_int n) ^ " expected) in " ^ (Parsifal.quote_string l))
         | e ->
            close_in f;
            raise e
       in
       iter_lines_aux new_accu line_handler f
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
        Unix.lockf wrfd Unix.F_LOCK 0;
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

  let list_csv_files () =
    list_dir [check_file_kind Unix.S_REG; check_extension ".csv"] data_dir
  in

  let iter_lines_accu csv_name line_handler initial_accu =
    let f = open_rfile csv_name in
    iter_lines_aux initial_accu line_handler f
  and iter_lines csv_name line_handler =
    let f = open_rfile csv_name in
    let modified_handler () = line_handler
    in iter_lines_aux () modified_handler f

  and reload_keys csv_name key_computation_fun =
    let f, _, keys = open_wfile csv_name in
    ignore (seek_in f 0);
    let line_handler () l =
      let key = key_computation_fun l in
      Hashtbl.replace keys key ()
    in
    iter_lines_aux () line_handler f
  and check_key_freshness csv_name key =
    let _, _, keys = open_wfile csv_name in
    not (Hashtbl.mem keys key)
  and write_line csv_name key line =
    let _, f, keys = open_wfile csv_name in
    output_string f (quote_csv_line line);
    output_string f "\n";
    Hashtbl.replace keys key ()

  and list_filetypes () =
    list_dir [check_file_kind Unix.S_DIR; remove_hidden_files] (data_dir ^ "/raw")
  and list_prefixes filetype =
    let filters = [check_file_kind Unix.S_REG; check_extension ".pack"]
    and dir = (data_dir ^ "/raw/" ^ filetype) in
    List.map (remove_extension ".pack") (list_dir filters dir)
  and list_files_by_prefix filetype name =
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
    let close_file _ (in_f, out_f, _) =
      close_in in_f;
      close_out out_f
    in
    Hashtbl.iter close_file open_wfiles;
    Hashtbl.clear open_wfiles;
    Hashtbl.iter close_file open_binfiles;
    Hashtbl.clear open_binfiles

  in
  { list_csv_files; iter_lines; iter_lines_accu;
    reload_keys; check_key_freshness; write_line;
    list_filetypes; list_prefixes; list_files_by_prefix;
    read_file; dump_file;
    close_all_files; }


let iter_raw_metadata ops filetype f =
  let handle_one_file metadata = f metadata in
  let handle_one_prefix prefix = List.iter handle_one_file (ops.list_files_by_prefix filetype prefix) in
  List.iter handle_one_prefix (ops.list_prefixes filetype)

let iter_raw_files ops filetype f =
  let real_f (n, _, _) = f n (ops.read_file filetype n) in
  iter_raw_metadata ops filetype real_f
