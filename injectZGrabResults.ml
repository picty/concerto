(* injectZGrabResults.ml

   Option:
    - stimulus

   Argument:
    - dump files

   Outputs:
    - campaigns.csv
    - answers.csv
    - chains.csv
    - certs
 *)

open Parsifal
open Getopt
open FileOps
open Stimulus
module Calendar = CalendarLib.Calendar;;


let verbose = ref false
let data_dir = ref ""
let campaign_id = ref 0

let update r v = r := Some v; ActionDone
let stimulus_name = ref None
let stimulus_id = ref None

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 'C') "campaign" (IntVal campaign_id) "override the campaign id (default is to use data from the dump.";

  mkopt None "stimulus-name" (StringFun (update stimulus_name)) "set the stimulus name (default is stimulus file name)";
  mkopt None "stimulus-id" (IntFun (update stimulus_id)) "set the stimulus id (default is campaign number)";
]

exception NotFound of (string * Yojson.Basic.json)


let assoc_of_json = function
  | `Assoc a -> a
  | _ -> failwith "assoc expected"

let get_json initial_json path =
  let path_list = string_split '.' path in
  let rec get_json_aux json = function
    | [] -> json
    | x::xs ->
       try get_json_aux (List.assoc x (assoc_of_json json)) xs
       with Not_found -> raise (NotFound (x, json))
  in
  get_json_aux initial_json path_list

let get_int_from_json json path = match get_json json path with
  | `Int i -> i
  | _ -> failwith "int expected"
  
let get_str_from_json json path = match get_json json path with
  | `String s -> s
  | _ -> failwith "string expected"

let get_bool_from_json json path = match get_json json path with
  | `Bool s -> s
  | _ -> failwith "bool expected"

let get_list_from_json json path = match get_json json path with
  | `List l -> l
  | _ -> failwith "list expected"

let translate_timestamp s =
  let timestamp_re =
    Str.regexp "^\\([0-9][0-9][0-9][0-9]\\)-\\([0-9][0-9]\\)-\\([0-9][0-9]\\)T\\([0-9][0-9]\\):\\([0-9][0-9]\\):\\([0-9][0-9]\\).\\([0-9][0-9]\\):\\([0-9][0-9]\\)$"
  in
  if Str.string_match timestamp_re s 0 then begin
    let y = int_of_string (Str.matched_group 1 s)
    and m = int_of_string (Str.matched_group 2 s)
    and d = int_of_string (Str.matched_group 3 s)
    and hh = int_of_string (Str.matched_group 4 s)
    and mm = int_of_string (Str.matched_group 5 s)
    and ss = int_of_string (Str.matched_group 6 s)
    and _hh_shift = int_of_string (Str.matched_group 7 s) (* TODO: Handle them! *)
    and _mm_shift = int_of_string (Str.matched_group 8 s) in
    Int64.of_float (Calendar.to_unixfloat (Calendar.make y m d hh mm ss))
  end else failwith "Invalid timestamp"


let handle_one_line stimulus_checks ops json_value =
  let is_version_compatible, is_suite_compatible, is_compression_compatible, _ = stimulus_checks in
  let ip_str = get_str_from_json json_value "ip"
  and campaign = string_of_int !campaign_id
  and name = try get_str_from_json json_value "domain" with NotFound _ -> ""
  and port = 443 (* TODO! *)
  and timestamp = translate_timestamp (get_str_from_json json_value "timestamp") in

  let answer_type, version, server_random, ciphersuite, alert_level, alert_type,
      version_compat, suite_compat, compression_compat, extensions_compat,
      secure_renego_supported, unchecked_certs =
    try
      let error = get_str_from_json json_value "error" in
      if (String.length error > 21) && 
           (String.sub error 0 20 = "remote error: alert(")
      then begin
        let alert_str = String.sub error 20 ((String.length error) - 21) in
        "11", "", "", "", "2", alert_str, "", "", "", "", "", []
      end else "1", "", "", "", "", "", "", "", "", "", "", []
    with NotFound ("error", _) ->
      let sh = get_json json_value "data.tls.server_hello" in
      let version = get_int_from_json sh "version.value"
      and server_random = get_str_from_json sh "random"
      and ciphersuite = get_int_from_json sh "cipher_suite.value"
      and compression = get_int_from_json sh "compression_method"
      and is_rfc5746_supported = get_bool_from_json sh "secure_renegotiation" in

      let cert_b64 = get_str_from_json json_value "data.tls.server_certificates.certificate.raw"
      and chain_b64 =
        try
          List.map (fun o -> get_str_from_json o "raw")
            (get_list_from_json json_value "data.tls.server_certificates.chain")
        with NotFound _ -> []
      in
      let debase64 s =
        let i = input_of_string "" s in
        Base64.parse_base64_container Base64.NoHeader "" BasePTypes.parse_rem_string i
      in
      let raw_certs = List.map debase64 (cert_b64::chain_b64) in
      (* TODO: Use a more generic file/hash facility? *)
      let unchecked_certs = List.map (X509Util.sc_of_raw_value "" false) raw_certs in

      "21", string_of_int version, server_random, string_of_int ciphersuite, "", "",
      (if is_version_compatible version then "1" else "0"),
      (if is_suite_compatible ciphersuite then "1" else "0"),
      (if is_compression_compatible compression then "1" else "0"), "1",
      (if is_rfc5746_supported then "1" else "0"),
      unchecked_certs
  in

  let chain_hash =
    if unchecked_certs = []
    then ""
    else CryptoUtil.sha1sum (String.concat "" (List.map X509Util.hash_of_sc unchecked_certs))
  in

  if ops.check_key_freshness "answers" (ip_str ^ campaign ^ name) then begin
    ops.write_line "answers" (ip_str ^ campaign ^ name)
      [campaign; ip_str; string_of_int port; name;
       Int64.to_string timestamp;
       answer_type; version; server_random; ciphersuite; alert_level; alert_type;
       hexdump chain_hash;
       version_compat; suite_compat; compression_compat; extensions_compat;
       secure_renego_supported
      ];

    if ops.check_key_freshness "chains" (hexdump chain_hash) then begin
      List.iteri (fun i -> fun sc -> ops.write_line "chains" (hexdump chain_hash)
        [hexdump chain_hash; string_of_int i; hexdump (X509Util.hash_of_sc sc)]) unchecked_certs;
    end
  end;

  let save_cert sc = ops.dump_file "certs" (hexdump (X509Util.hash_of_sc sc)) (X509Util.raw_value_of_sc sc)
  in List.iter save_cert unchecked_certs


let handle_one_file stimulus_checks ops f =
  let rec aux () =
    let line = 
      try Some (input_line f)
      with End_of_file -> None
    in
    match line with
    | None -> close_in f
    | Some l ->
       let json = Yojson.Basic.from_string l in
       handle_one_line stimulus_checks ops json;
       aux ()
  in
  aux ()


let _ =
  X509Util.relax_x509_constraints ();
  let zgrab_files = parse_args ~progname:"injectZGrabResults" options Sys.argv in
  if !data_dir = "" then usage "injectZGrabResults" options (Some "Please provide a valid data directory");
  try
    let ops = prepare_data_dir !data_dir in
    ops.reload_keys "chains" (List.hd);
    let real_stimulus_id, stimulus_checks = extract_stimulus_checks !stimulus_name !stimulus_id ops in
    begin
      match real_stimulus_id with
      | None -> ()
      | Some sid -> ops.write_line "campaigns" "" [string_of_int !campaign_id; string_of_int sid]
    end;

    if zgrab_files = []
    then handle_one_file stimulus_checks ops stdin
    else List.iter (fun fn -> handle_one_file stimulus_checks ops (open_in fn)) zgrab_files;
    ops.close_all_files ()
  with
    | NotFound (field_name, json) -> 
      let pretty = Yojson.Basic.pretty_to_string ~std:true json in
      prerr_endline ("Unable to find \"" ^ field_name ^ "\" in " ^ pretty)
    | e ->
      let current_prog = String.concat " " (Array.to_list Sys.argv) in
      prerr_endline ("[" ^ current_prog ^ "] " ^ (Printexc.to_string e)); exit 1
