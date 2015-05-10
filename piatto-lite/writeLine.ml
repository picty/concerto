open FileOps

let _ =
  if Array.length Sys.argv < 5 then exit 1;

  let ops = prepare_csv_output_dir Sys.argv.(1) in
  ops.write_line Sys.argv.(2) Sys.argv.(3) (Array.to_list (Array.sub Sys.argv 4 ((Array.length Sys.argv) - 4)))
                                                             
