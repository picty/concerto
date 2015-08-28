open FileOps

module StringSet = Set.Make(String)


let handle_trusted_chain_line chain_sets = function
  | [chain_hash; built_chain_number; trust_flag] ->
     begin
       try
         let h = Hashtbl.find chain_sets trust_flag in
         Hashtbl.add h chain_hash (int_of_string built_chain_number);
       with Not_found -> ()
     end
  | _ -> raise (InvalidNumberOfFields 3)

let load_trusted_chains ops trust_flags =
  let chain_sets = Hashtbl.create 10 in
  if trust_flags <> [] then begin
    List.iter (fun trust_flag -> Hashtbl.add chain_sets trust_flag (Hashtbl.create 1000)) trust_flags;
    ops.iter_lines "trusted_chains" (handle_trusted_chain_line chain_sets);
  end;
  chain_sets


let handle_chain_validity_line chain_validities = function
  | [chain_hash; built_chain_number_str; _; _; _; _; _; nb_str; na_str; _] ->
     let built_chain_number = int_of_string built_chain_number_str in
     Hashtbl.replace chain_validities (chain_hash, built_chain_number) (Int64.of_string nb_str, Int64.of_string na_str)
  | _ -> raise (InvalidNumberOfFields 10)

let load_chain_validities ops =
  let chain_validities = Hashtbl.create 1000 in
  ops.iter_lines "built_chains" (handle_chain_validity_line chain_validities);
  chain_validities


let is_flagged_with chain_sets trust_flag chain_hash =
  let h = Hashtbl.find chain_sets trust_flag in
  Hashtbl.mem h chain_hash

let is_flagged_and_valid chain_sets chain_validities trust_flag chain_hash timestamp =
  let h = Hashtbl.find chain_sets trust_flag in
  let built_chain_numbers = Hashtbl.find_all h chain_hash in
  let check_validity n =
    try
      let nb, na = Hashtbl.find chain_validities (chain_hash, n) in
      timestamp >= nb && timestamp <= na
    with Not_found -> false
  in
  List.fold_left (||) false (List.map check_validity built_chain_numbers)


let inc_in_hashtbl h k =
  try Hashtbl.replace h k ((Hashtbl.find h k) + 1)
  with Not_found -> Hashtbl.replace h k 1

