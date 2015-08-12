open FileOps

let _ =
  if Array.length Sys.argv <> 2 then exit 1;
  let ops = prepare_data_dir Sys.argv.(1) in
  List.iter print_endline (ops.list_csv_files ())
