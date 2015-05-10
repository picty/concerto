open FileOps

let _ =
  if Array.length Sys.argv <> 4 then exit 1;

  let ops = prepare_csv_output_dir Sys.argv.(1) in
  let print_file (name, offset, len) =
    Printf.printf "%s:%d:%d\n" name offset len
  in List.iter print_file (ops.list_files Sys.argv.(2) Sys.argv.(3))
