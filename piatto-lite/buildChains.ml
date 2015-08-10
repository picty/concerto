open Parsifal
open Getopt
open FileOps
open X509Util

let verbose = ref false
let data_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
]




(* let hexparse s = *)
(*   let tmp_input = input_of_string s s in *)
(*   PTypes.hexparse tmp_input *)

let read_links ops =
  let links = Hashtbl.create 1000 in
  let read_links_aux = function
    | [subject_h; issuer_h] -> Hashtbl.add links subject_h issuer_h;
    | _ -> raise (InvalidNumberOfFields 2)
  in
  ops.iter_lines "links" read_links_aux;
  links



let build_certchain max_transvalid links certs_hash =

  let rec bottom_up n_ordered n_transvalid ((_, last_hash) as last) chain (next_certs : (int * string) list) =
    let possible_issuers = Hashtbl.find_all links last_hash in

    (* First, we check wether we have hit a self-signed cert *)
    if List.mem last_hash possible_issuers
    then [ last::chain, next_certs, true, n_ordered, n_transvalid ]

    else begin
      (* Else, we need to find candidates for the next link, starting with
	 certificates present in next_certs, then moving on with CA roots,
	 and ending with other CAs we might know. *)

      let rec prepare_inmsg_candidates n_ordered previous_certs accu = function
	| [] -> accu
	| ((c_pos, c_hash) as c)::cs ->
	   let new_previous_certs = (c::previous_certs) in
	   if (List.mem c_hash possible_issuers) &&
             not (List.mem c_hash (List.map snd (last::chain))) &&
	       not (List.mem c_hash (List.map snd previous_certs))
	   then begin
             let new_n_ordered =
               if n_ordered - 1 = (List.length chain) && c_pos = n_ordered
               then  n_ordered + 1
               else n_ordered
             in
             let new_accu = (new_n_ordered, n_transvalid, (Some c_pos, c_hash), List.rev_append previous_certs cs)::accu in
	     prepare_inmsg_candidates n_ordered new_previous_certs new_accu cs
	  end else prepare_inmsg_candidates n_ordered new_previous_certs accu cs
      in
      let rec prepare_external_cas n_ordered rem_certs accu = function
	| [] -> accu
	| ca::cas ->
	  let new_accu =
	    if not (List.mem ca (List.map (fun (_, _, (_, c), _) -> c) accu)) &&
              not (List.mem ca (List.map snd (last::chain)))
              (* && not (List.mem (cert_id_of_sc sc) (List.map cert_id_of_sc (last::chain))) *)
	    then (n_ordered, n_transvalid + 1, (None, ca), rem_certs)::accu
	    else accu
	  in prepare_external_cas n_ordered rem_certs new_accu cas
      in

      let c1 = prepare_inmsg_candidates n_ordered [] [] next_certs in
      let candidates =
        let look_into_external = match max_transvalid with
          | None -> true
          | Some max -> n_transvalid < max
        in
        if look_into_external
        then prepare_external_cas n_ordered next_certs c1 possible_issuers
        else c1
      in

      match candidates with
      (* If no acceptable issuer has been found, this branch is an incomplete chain *)
      | [] -> [ last::chain, next_certs, false, n_ordered, n_transvalid ]
      | _ ->
         let handle_candidate (n_ordered2, n_transvalid2, n, rems) =
           bottom_up n_ordered2 n_transvalid2 n (last::chain) rems
         in
         List.flatten (List.map handle_candidate candidates)
    end
  in
  match List.mapi (fun i c -> (i, c)) certs_hash with
  | (0, c)::cs -> bottom_up 1 0 (Some 0, c) [] cs
  | (_, _)::_ -> failwith "Internal error"
  | [] -> []




let handle_chains_file links ops =
  let handle_current_chain = function
    | None -> ()
    | Some (chain_h, unordered_certs_h) ->
       let ordered_certs_h = List.sort compare unordered_certs_h in
       let check_i i (n, cert) =
         if i = n
         then cert
         else failwith ("Unexpected line in chains.csv concerning chain \"" ^ (quote_string chain_h) ^ "\"")
       in
       let certs_h = List.mapi check_i ordered_certs_h in
       let built_chains = build_certchain (Some 5) links certs_h in
       let write_built_chain i (certs_hash, unused_certs, complete, n_ordered, n_transvalid) =
         ops.write_line "built_chains" "" [
           chain_h;
           string_of_int i;
           string_of_int (List.length certs_hash);
           if complete then "1" else "0";
           string_of_int n_ordered;
           string_of_int n_transvalid;
         ];
         List.iteri (fun pos_in_chain (pos_in_msg, cert_hash) -> ops.write_line "built_links" "" [chain_h; string_of_int i; string_of_int pos_in_chain; (match pos_in_msg with None -> "-" | Some i -> string_of_int i); cert_hash]) (List.rev certs_hash);
         List.iter (fun (pos_in_msg, cert_hash) -> ops.write_line "unused_certs" "" [chain_h; string_of_int i; string_of_int pos_in_msg; cert_hash]) unused_certs
       in
       List.iteri write_built_chain built_chains
  in

  let handle_one_line current_chain l = match l, current_chain with
    | [chain_h; n_str; cert_h], None ->
       let n = int_of_string n_str in
       Some (chain_h, [n, cert_h])
    | [chain_h; n_str; cert_h], Some (prev_chain_h, prev_certs) ->
       let n = int_of_string n_str in
       if chain_h <> prev_chain_h then begin
          handle_current_chain current_chain;
	  Some (chain_h, [n, cert_h])
        end else Some (chain_h, (n, cert_h)::prev_certs)
    | _ -> raise (InvalidNumberOfFields 3)
  in
  let last_chain = ops.iter_lines_accu "chains" handle_one_line None in
  handle_current_chain last_chain




let _ =
  (* TODO: Check that this _ is [] *)
  let _ = parse_args ~progname:"buildChains" options Sys.argv in
  try
    let ops = prepare_data_dir !data_dir in
    let links = read_links ops in
    if !verbose then print_endline "Links loaded.";
    handle_chains_file links ops;
    ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
