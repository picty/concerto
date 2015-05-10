open FileOps

let _ =
  if Array.length Sys.argv <> 4 then exit 1;

  let ops = prepare_csv_output_dir Sys.argv.(1) in
  print_string (ops.read_file Sys.argv.(2) Sys.argv.(3))
