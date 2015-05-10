open FileOps

let _ =
  if Array.length Sys.argv <> 5 then exit 1;

  let ops = prepare_csv_output_dir Sys.argv.(1) in
  ops.dump_file Sys.argv.(2) Sys.argv.(3) (Parsifal.get_file_content Sys.argv.(4))
