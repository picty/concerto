open FileOps

module StringSet = Set.Make(String)


let handle_trusted_chain_line chain_sets = function
  | [chain_hash; _; trust_flag] ->
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


let is_flagged_with chain_sets trust_flag chain_hash =
  let s = Hashtbl.find chain_sets trust_flag in
  StringSet.mem chain_hash s


let inc_in_hashtbl h k =
  try Hashtbl.replace h k ((Hashtbl.find h k) + 1)
  with Not_found -> Hashtbl.replace h k 1

