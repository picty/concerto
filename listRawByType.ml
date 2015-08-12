open FileOps

let _ =
  if Array.length Sys.argv <> 3 then exit 1;

  let ops = prepare_data_dir Sys.argv.(1) in
  let print_file (name, offset, len) =
    Printf.printf "%s:%d:%d\n" name offset len
  in iter_raw_metadata ops Sys.argv.(2) print_file
