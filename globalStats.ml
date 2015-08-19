(* globalStats.ml

   Inputs:
    - answers.csv

   Option:
    - campaign id
 *)

open Getopt
open FileOps

let data_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
]


let update_count counts = function
  | [campaign_str; _; _; _; _; answer_type_str; _; _; _; _; _] ->
     let campaign = int_of_string campaign_str
     and answer_type = int_of_string answer_type_str in

     let campaign_h =
       try Hashtbl.find counts campaign
       with Not_found ->
         let h = Hashtbl.create 1000 in
         Hashtbl.replace counts campaign h;
         h
     in

     begin
       try Hashtbl.replace campaign_h answer_type ((Hashtbl.find campaign_h answer_type) + 1)
       with Not_found -> Hashtbl.replace campaign_h answer_type 1
     end

  | _ -> raise (InvalidNumberOfFields 11)

let print_count_for_one_campaign campaign h =
  Printf.printf "= %d =\n" campaign;
  let total = Hashtbl.fold (fun _ n accu -> accu+n) h 0 in
  Printf.printf "Total: %10d\n" total;
  Hashtbl.iter (fun t c ->  Printf.printf "%5d: %10d\n" t c) h;
  print_newline ()


let _ =
  let _ = parse_args ~progname:"globalStats" options Sys.argv in
  if !data_dir = "" then usage "globalStats" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in
    let counts = Hashtbl.create 10 in
    ops.iter_lines "answers" (update_count counts);
    Hashtbl.iter print_count_for_one_campaign counts;
    ops.close_all_files ()
  with
    | e -> prerr_endline (Printexc.to_string e); exit 1
