let rec handle_lines f =
  let line =
    try Some (input_line f)
    with End_of_file -> None
  in
  match line with
  | None -> ()
  | Some l ->
     let json = Yojson.Safe.from_string l in
     let pretty = Yojson.Safe.pretty_to_string ~std:true json in
     print_endline pretty;
     print_newline ();
     handle_lines f

let _ =
  handle_lines stdin
