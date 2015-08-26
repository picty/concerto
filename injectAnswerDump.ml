(* injectAnswerDump.ml

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
open Lwt
open LwtUtil
open AnswerDump
open Ssl2
open Tls
open TlsEnums
open X509Util
open AnswerDumpUtil
open FileOps


let verbose = ref false
let data_dir = ref ""
let campaign_id = ref None

let update r v = r := Some v; ActionDone
let stimulus_name = ref None
let stimulus_id = ref None

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 'C') "campaign" (IntFun (update campaign_id)) "override the campaign id (default is to use data from the dump.";

  mkopt None "stimulus-name" (StringFun (update stimulus_name)) "set the stimulus name (default is stimulus file name)";
  mkopt None "stimulus-id" (IntFun (update stimulus_id)) "set the stimulus id (default is campaign number)";
]

let get_campaign_from_dump a =
  string_of_int a.campaign

let get_campaign_from_cmdline id =
  let value = string_of_int id in
  fun _a -> value

let rec handle_one_file get_campaign stimulus_checks ops input =
  let is_version_compatible, is_suite_compatible, is_compression_compatible, are_extensions_compatible = stimulus_checks in
  let finalize_ok answer =
    let ip_str = string_of_v2_ip answer.ip_addr in
    let campaign = get_campaign answer in
    (* TODO: Is this useful? *)
    enrich_record_content := true;
    let parsed_answer = parse_answer DefaultEnrich false answer in

    let raw_certs = match parsed_answer.pa_content with
      | TLSHandshake h -> h.certificates
      | SSLv2Handshake h -> [h.certificate]
      | _ -> []
    in
    (* TODO: Handle broken certificates in a better way? *)
    let unchecked_certs = List.mapi (sc_of_cert_in_hs_msg false ip_str) raw_certs in

    let answer_type, version, ciphersuite, alert_level, alert_type,
      version_compat, suite_compat, compression_compat, extensions_compat = match parsed_answer.pa_content with
      | Empty -> "0", "", "", "", "", "", "", "", ""
      | Junk _ -> "1", "", "", "", "", "", "", "", ""
      | SSLv2Handshake {version = v; cipher_specs = []} ->
         let v_int = int_of_tls_version v in
         "20", string_of_int v_int, "", "", "",
           (if is_version_compatible v_int then "1" else "0"), "", "", ""

      | SSLv2Alert e ->
         "10", "2", "", "2", string_of_int (int_of_ssl2_error e), "", "", "", ""
      | TLSAlert (v, al, at) ->
         "11", string_of_int (int_of_tls_version v), "",
         string_of_int (int_of_tls_alert_level al), string_of_int (int_of_tls_alert_type at),
         "", "", "", ""

      | SSLv2Handshake {version = v; cipher_specs = c::_} ->
         let v_int = int_of_tls_version v
         and c_int = int_of_ciphersuite c in
         "20", string_of_int v_int, string_of_int c_int, "", "",
         (if is_version_compatible v_int then "1" else "0"),
         (if is_suite_compatible c_int then "1" else "0"), "1", "1"
      | TLSHandshake h ->
         let v_int = int_of_tls_version h.server_hello_version
         and c_int = int_of_ciphersuite h.ciphersuite in
         "21", string_of_int v_int, string_of_int c_int, "", "",
         (if is_version_compatible v_int then "1" else "0"),
         (if is_suite_compatible c_int then "1" else "0"),
         (if is_compression_compatible (int_of_compression_method h.compression_method) then "1" else "0"),
         (if are_extensions_compatible h.extensions then "1" else "0")
    in

    let chain_hash =
      if unchecked_certs = []
      then ""
      else CryptoUtil.sha1sum (String.concat "" (List.map hash_of_sc unchecked_certs))
    in
    if ops.check_key_freshness "answers" (ip_str ^ campaign ^ answer.name) then begin
      ops.write_line "answers" (ip_str ^ campaign ^ answer.name)
        [campaign; ip_str; string_of_int answer.port; answer.name;
         Int64.to_string answer.timestamp;
         answer_type; version; ciphersuite; alert_level; alert_type;
         hexdump chain_hash;
         version_compat; suite_compat; compression_compat; extensions_compat;
        ];

      if ops.check_key_freshness "chains" (hexdump chain_hash) then begin
	List.iteri (fun i -> fun sc -> ops.write_line "chains" (hexdump chain_hash)
	  [hexdump chain_hash; string_of_int i; hexdump (hash_of_sc sc)]) unchecked_certs;
      end;

      let save_cert sc = ops.dump_file "certs" (hexdump (hash_of_sc sc)) (raw_value_of_sc sc)
      in List.iter save_cert unchecked_certs
    end;
    handle_one_file get_campaign stimulus_checks ops input

  and finalize_nok = function
    | (ParsingException _) as e ->
      if input.lwt_eof && (input.string_input.cur_length = 0)
      then return ()
      else fail e
    | e -> fail e

  in try_bind (fun () -> lwt_parse_wrapper parse_answer_dump_v2 input) finalize_ok finalize_nok


let extract_stimulus_versions result = function
  | [id_str; name; min_version; max_version] ->
     let id = int_of_string id_str in
     if !stimulus_id = Some id || !stimulus_name = Some name
     then begin
       stimulus_id := Some id;
       Some (id, int_of_string min_version, int_of_string max_version)
     end else result
  | _ -> result

let extract_stimulus_params results = function
  | [id_str; suite_str] ->
     let id = int_of_string id_str
     and suite = int_of_string suite_str in
     if !stimulus_id = Some id
     then suite::results
     else results
  | _ -> results


let extract_stimulus_checks ops =
  let stimulus_info = match !stimulus_name, !stimulus_id with
    | None, None -> None
    | _ ->
       match ops.iter_lines_accu "stimuli" extract_stimulus_versions None with
       | None -> None
       | Some (stimulus_id, min_version, max_version) ->
          let suites = ops.iter_lines_accu "stimuli_suites" extract_stimulus_params []
          and compressions = ops.iter_lines_accu "stimuli_compressions" extract_stimulus_params []
          and extensions = ops.iter_lines_accu "stimuli_extensions" extract_stimulus_params [] in
          Some (stimulus_id, min_version, max_version, suites, compressions, extensions)
  in
  match stimulus_info with
  | None ->
     let always_true _ = true in
     always_true, always_true, always_true, always_true
  | Some (stimulus_id, min_version, max_version, suites, compressions, extensions) ->
     begin
       match !campaign_id with
       | None -> ()
       | Some cid -> ops.write_line "campaigns" "" [string_of_int cid; string_of_int stimulus_id]
     end;
     let is_version_compatible v = min_version <= v && max_version >= v
     and is_suite_compatible s = s <> 0x00ff && List.mem s suites
     and is_compression_compatible c = List.mem c compressions
     and is_extension_compatible e =
       (e = 65281 && List.mem 0x00ff suites) ||
         List.mem e extensions
     in
     let are_extensions_compatible = function
       | None -> true
       | Some exts ->
          let ext_types = List.map (fun e -> int_of_extension_type e.extension_type) exts in
          List.fold_left (&&) true (List.map is_extension_compatible ext_types)
     in
     is_version_compatible, is_suite_compatible, is_compression_compatible, are_extensions_compatible

let _ =
  let dump_files = parse_args ~progname:"injectAnswerDump" options Sys.argv in
  if !data_dir = "" then usage "injectAnswerDump" options (Some "Please provide a valid data directory");
  try
    let get_campaign = match !campaign_id with
      | None -> get_campaign_from_dump
      | Some id -> get_campaign_from_cmdline id
    and ops = prepare_data_dir !data_dir in
    ops.reload_keys "chains" (List.hd);
    let stimulus_checks = extract_stimulus_checks ops in
    let open_files = function
      | [] -> input_of_channel ~verbose:(!verbose) "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
      | _ -> Lwt_list.map_s input_of_filename dump_files
    in
    Lwt_unix.run (open_files dump_files >>= Lwt_list.iter_s (handle_one_file get_campaign stimulus_checks ops));
    ops.close_all_files ()
  with
    | ParsingException (e, h) -> 
      let current_prog = String.concat " " (Array.to_list Sys.argv) in
      prerr_endline ("[" ^ current_prog ^ "] " ^ (string_of_exception e h)); exit 1
    | e ->
      let current_prog = String.concat " " (Array.to_list Sys.argv) in
      prerr_endline ("[" ^ current_prog ^ "] " ^ (Printexc.to_string e)); exit 1
