open FileOps

module StringSet = Set.Make(String)


let handle_trusted_chain_line chain_sets = function
  | [chain_hash; trust_flag] ->
     begin
       try
         let s = Hashtbl.find chain_sets trust_flag in
         Hashtbl.replace chain_sets trust_flag (StringSet.add chain_hash s)
       with Not_found -> ()
     end
  | _ -> raise (InvalidNumberOfFields 3)

let load_trusted_chains ops trust_flags =
  let chain_sets = Hashtbl.create 10 in
  if trust_flags <> [] then begin
    List.iter (fun trust_flag -> Hashtbl.add chain_sets trust_flag StringSet.empty) trust_flags;
    ops.iter_lines "trusted_chains" (handle_trusted_chain_line chain_sets);
  end;
  chain_sets


let handle_chain_validity_line chain_validities = function
  | [chain_hash; _; _; _; _; _; _; nb_str; na_str; _] ->
     Hashtbl.add chain_validities chain_hash (Int64.of_string nb_str, Int64.of_string na_str)
  | _ -> raise (InvalidNumberOfFields 10)

let load_chain_validities ops =
  let chain_validities = Hashtbl.create 1000 in
  ops.iter_lines "built_chains" (handle_chain_validity_line chain_validities);
  chain_validities


let is_flagged_with chain_sets trust_flag chain_hash =
  let s = Hashtbl.find chain_sets trust_flag in
  StringSet.mem chain_hash s

let is_flagged_and_valid chain_sets chain_validities trust_flag chain_hash timestamp =
  let s = Hashtbl.find chain_sets trust_flag in
  if StringSet.mem chain_hash s then begin
    let validities = Hashtbl.find_all chain_validities chain_hash in
    let check_validity (nb, na) = timestamp >= nb && timestamp <= na in
    List.fold_left (||) false (List.map check_validity validities)
  end else false


let inc_in_hashtbl h k =
  try Hashtbl.replace h k ((Hashtbl.find h k) + 1)
  with Not_found -> Hashtbl.replace h k 1

