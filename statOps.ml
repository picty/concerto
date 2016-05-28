open ConcertoUtils
open FileOps

let handle_trusted_chain_line chain_sets = function
  | [chain_hash; trust_flag] ->
     begin
       try
         let s = Hashtbl.find chain_sets trust_flag in
         Hashtbl.replace chain_sets trust_flag (StringSet.add chain_hash s)
       with Not_found -> ()
     end
  | _ -> raise (InvalidNumberOfFields 2)

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


let handle_chain_quality_line chain_details = function
  | [chain_h; n; _; complete_str; ordered_str; n_transvalid_str; n_unused_str; nb_str; na_str; algos_str] ->
     let complete = complete_str = "1"
     and ordered = ordered_str = "1"
     and n_transvalid = int_of_string n_transvalid_str
     and n_unused = int_of_string n_unused_str
     and nb = Int64.of_string nb_str
     and na = Int64.of_string na_str
     and algos = key_typesize_of_string algos_str in
     let details = complete, ordered, n_unused, n_transvalid, nb, na in
     let quality = chain_quality_of_details details in
     (* TODO: Here, we might want to check for validity period...  but
        this means we have to keep all chain information, which can be
        too big in large campaigns...  So we only keep all the chains in
        the best category, which is an approximation.*)
     let new_info = (quality, nb, na, algos) in
     begin
       try
         let current_quality, _, _, _ = Hashtbl.find chain_details chain_h in
         if compare_chain_quality current_quality quality < 0 && nb < na
         then Hashtbl.replace chain_details chain_h new_info
       with Not_found -> Hashtbl.replace chain_details chain_h new_info
     end
  | _ -> raise (InvalidNumberOfFields 10)

let load_chain_qualities ops =
  let chain_qualities = Hashtbl.create 1000 in
  ops.iter_lines "built_chains" (handle_chain_quality_line chain_qualities);
  chain_qualities



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

