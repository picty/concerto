open Getopt
open FileOps

let data_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'o') "data-dir" (StringVal data_dir) "set the data directory";
]

let component_by_id = Hashtbl.create 1000
let id_by_hash = Hashtbl.create 1000

let search h =
  try Some (Hashtbl.find id_by_hash h)
  with Not_found -> None

let add_to cid x =
  let c = Hashtbl.find component_by_id cid in
  Hashtbl.replace c x ();
  Hashtbl.replace id_by_hash x cid

let create_new_component cid xs =
  let c = Hashtbl.create 100 in
  Hashtbl.replace component_by_id cid c;
  List.iter (add_to cid) xs

let add_to_component cid xs =
  List.iter (add_to cid) xs

let merge_components cid1 cid2 =
  let c1 = Hashtbl.find component_by_id cid1
  and c2 = Hashtbl.find component_by_id cid2 in
  let move_from_c2_to_c1 x _ =
    Hashtbl.replace c1 x ();
    Hashtbl.replace id_by_hash x cid1
  in
  Hashtbl.iter move_from_c2_to_c1 c2;
  Hashtbl.remove component_by_id cid2

    
  
let handle_link = function
  | [subject_h; issuer_h] ->
    if subject_h <> issuer_h then begin
      match search subject_h, search issuer_h with
      | None, None -> create_new_component subject_h [subject_h; issuer_h]
      | Some cid, None | None, Some cid -> add_to_component cid [subject_h; issuer_h]
      | Some cid1, Some cid2 ->
        if cid1 == cid2
        then add_to_component cid1 [subject_h; issuer_h]
        else merge_components cid1 cid2
    end else begin
      match search subject_h with
      | None -> create_new_component subject_h [subject_h]
      | Some _ -> ()
    end;
  | _ -> raise (InvalidNumberOfFields 2)


let _ =
  let csv_files = match parse_args ~progname:"computeComponents" options Sys.argv with
    | [] -> ["links"]
    | l -> l
  in
  try
    let ops = prepare_data_dir !data_dir in
    List.iter (fun csv -> ops.iter_lines csv handle_link) csv_files;
    print_string "N_components: ";
    print_int (Hashtbl.length component_by_id);
    print_newline ();
    let print_cert h _ = print_endline h in
    let print_component _ c = print_int (Hashtbl.length c); print_newline (); Hashtbl.iter print_cert c; print_newline () in
    Hashtbl.iter print_component component_by_id;
    ops.close_all_files ()
  with e -> prerr_endline (Printexc.to_string e); exit 1
