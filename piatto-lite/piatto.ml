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
open CsvOps


let verbose = ref false
let output_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'o') "output-dir" (StringVal output_dir) "set the output directory for dump2html or dump2csv";
]


let rec handle_one_file ops input =
  let finalize_ok answer =
    let ip_str = string_of_v2_ip answer.ip_addr in
    let campaign = string_of_int answer.campaign in
    (* TODO: Is this useful? *)
    enrich_record_content := true;
    let parsed_answer = parse_answer DefaultEnrich false answer in

    let raw_certs = match parsed_answer.pa_content with
      | TLSHandshake (_, _, _, certs) -> certs
      | SSLv2Handshake (_, _, cert) -> [cert]
      | _ -> []
    in
    (* TODO: Handle broken certificates in a better way? *)
    let unchecked_certs = List.mapi (sc_of_cert_in_hs_msg false ip_str) raw_certs in

    let answer_type, version, ciphersuite, alert_level, alert_type = match parsed_answer.pa_content with
      | Empty -> "0", "", "", "", ""
      | Junk _ -> "1", "", "", "", ""
      | SSLv2Handshake (v, [], _) -> string_of_int (int_of_tls_version v), "", "", "", ""

      | SSLv2Alert e ->
         "10", "2", "", "2", string_of_int (int_of_ssl2_error e)
      | TLSAlert (v, al, at) ->
         "11", string_of_int (int_of_tls_version v), "",
         string_of_int (int_of_tls_alert_level al), string_of_int (int_of_tls_alert_type at)

      | SSLv2Handshake (v, c::_, _) ->
         "20", string_of_int (int_of_tls_version v), string_of_int (int_of_ciphersuite c), "", ""
      | TLSHandshake (_, v, c, _) ->
         "21", string_of_int (int_of_tls_version v), string_of_int (int_of_ciphersuite c), "", ""
    in

    let chain_hash = CryptoUtil.sha1sum (String.concat "" (List.map hash_of_sc unchecked_certs)) in
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

      let save_cert sc = ops.dump_file (hexdump (hash_of_sc sc)) (raw_value_of_sc sc)
      in List.iter save_cert unchecked_certs
    end;
    handle_one_file ops input

  and finalize_nok = function
    | (ParsingException _) as e ->
      if input.lwt_eof && (input.string_input.cur_length = 0)
      then return ()
      else fail e
    | e -> fail e

  in try_bind (fun () -> lwt_parse_wrapper parse_answer_dump_v2 input) finalize_ok finalize_nok



let _ =
  let dump_files = parse_args ~progname:"piatto" options Sys.argv in
  try
    let ops = prepare_csv_output_dir !output_dir in
    let open_files = function
      | [] -> input_of_channel ~verbose:(!verbose) "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
      | _ -> Lwt_list.map_s input_of_filename dump_files
    in
    Lwt_unix.run (open_files dump_files >>= Lwt_list.iter_s (handle_one_file ops));
    ops.close_all_files ()
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
