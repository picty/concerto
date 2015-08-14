(* injectAnswerDump.ml

   Argument:
    - dump files

   Outputs:
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
let update_campaign_id id = campaign_id := Some id; ActionDone


let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'd') "data-dir" (StringVal data_dir) "set the data directory";
  mkopt (Some 'C') "campaign" (IntFun update_campaign_id) "override the campaign id (default is to use data from the dump.";
]

let get_campaign_from_dump a =
  string_of_int a.campaign

let get_campaign_from_cmdline id =
  let value = string_of_int id in
  fun _a -> value

let rec handle_one_file get_campaign ops input =
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

    let answer_type, version, ciphersuite, alert_level, alert_type = match parsed_answer.pa_content with
      | Empty -> "0", "", "", "", ""
      | Junk _ -> "1", "", "", "", ""
      | SSLv2Handshake {version = v; cipher_specs = []} -> "20", string_of_int (int_of_tls_version v), "", "", ""

      | SSLv2Alert e ->
         "10", "2", "", "2", string_of_int (int_of_ssl2_error e)
      | TLSAlert (v, al, at) ->
         "11", string_of_int (int_of_tls_version v), "",
         string_of_int (int_of_tls_alert_level al), string_of_int (int_of_tls_alert_type at)

      | SSLv2Handshake {version = v; cipher_specs = c::_} ->
         "20", string_of_int (int_of_tls_version v), string_of_int (int_of_ciphersuite c), "", ""
      | TLSHandshake h ->
         "21",
         string_of_int (int_of_tls_version h.server_hello_version),
         string_of_int (int_of_ciphersuite h.ciphersuite), "", ""
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
         hexdump chain_hash];

      if ops.check_key_freshness "chains" chain_hash then begin
	List.iteri (fun i -> fun sc -> ops.write_line "chains" chain_hash
	  [hexdump chain_hash; string_of_int i; hexdump (hash_of_sc sc)]) unchecked_certs;
      end;

      let save_cert sc = ops.dump_file "certs" (hexdump (hash_of_sc sc)) (raw_value_of_sc sc)
      in List.iter save_cert unchecked_certs
    end;
    handle_one_file get_campaign ops input

  and finalize_nok = function
    | (ParsingException _) as e ->
      if input.lwt_eof && (input.string_input.cur_length = 0)
      then return ()
      else fail e
    | e -> fail e

  in try_bind (fun () -> lwt_parse_wrapper parse_answer_dump_v2 input) finalize_ok finalize_nok



let _ =
  let dump_files = parse_args ~progname:"injectAnswerDump" options Sys.argv in
  if !data_dir = "" then usage "inject" options (Some "Please provide a valid data directory");
  try
    let get_campaign = match !campaign_id with
      | None -> get_campaign_from_dump
      | Some id -> get_campaign_from_cmdline id
    and ops = prepare_data_dir !data_dir in
    let open_files = function
      | [] -> input_of_channel ~verbose:(!verbose) "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
      | _ -> Lwt_list.map_s input_of_filename dump_files
    in
    Lwt_unix.run (open_files dump_files >>= Lwt_list.iter_s (handle_one_file get_campaign ops));
    ops.close_all_files ()
  with
    | ParsingException (e, h) -> 
      let current_prog = String.concat " " (Array.to_list Sys.argv) in
      prerr_endline ("[" ^ current_prog ^ "] " ^ (string_of_exception e h)); exit 1
    | e ->
      let current_prog = String.concat " " (Array.to_list Sys.argv) in
      prerr_endline ("[" ^ current_prog ^ "] " ^ (Printexc.to_string e)); exit 1
