open Parsifal
open TlsEnums
open Tls
open Ssl2
open FileOps


let parse_stimulus raw_content =
  let i = input_of_string ~enrich:AlwaysEnrich "ClientHello" raw_content in
  let tls_record = try_parse (parse_tls_record None) i in
  match tls_record with
  | Some {
      record_content = Handshake {
        handshake_content = ClientHello {
          client_version = v;
          ciphersuites = cs;
          compression_methods = comps;
          client_extensions = None;
        }
      }
    } -> 0x0300, int_of_tls_version v, List.map int_of_ciphersuite cs,
         List.map int_of_compression_method comps, []
  | Some {
      record_content = Handshake {
        handshake_content = ClientHello {
          client_version = v;
          ciphersuites = cs;
          compression_methods = comps;
          client_extensions = Some es;
        }
      }
    } ->
     0x0300, int_of_tls_version v, List.map int_of_ciphersuite cs,
     List.map int_of_compression_method comps,
     List.map (fun e -> int_of_extension_type e.extension_type) es

  | Some _ -> failwith "Invalid stimulus: this TLS Record is not a valid ClientHello"

  | None ->
     let ssl2_record = try_parse (parse_ssl2_record { Ssl2.cleartext = true }) i in
     match ssl2_record with
     | Some {
         ssl2_content = SSL2Handshake {
           ssl2_handshake_content = SSL2ClientHello ch
         }
       } ->
        2, int_of_tls_version ch.ssl2_client_version,
        List.map int_of_ciphersuite ch.ssl2_client_cipher_specs, [0], []

     | Some _ -> failwith "Invalid stimulus: this SSLv2 Record is not a valid ClientHello"
                          
     | None -> failwith "Invalid stimulus: this is neither an SSLv2 nor TLS ClientHello"



let extract_stimulus_versions_by_name stimulus_name result = function
  | [id_str; name; min_version; max_version] ->
     if stimulus_name = name
     then Some (int_of_string id_str, int_of_string min_version, int_of_string max_version)
     else result
  | _ -> result

let extract_stimulus_versions_by_id stimulus_id result = function
  | [id_str; _; min_version; max_version] ->
     if stimulus_id = int_of_string id_str
     then Some (stimulus_id, int_of_string min_version, int_of_string max_version)
     else result
  | _ -> result

let extract_stimulus_params stimulus_id results = function
  | [id_str; param_str] ->
     if stimulus_id = int_of_string id_str
     then (int_of_string param_str)::results
     else results
  | _ -> results


let extract_stimulus_checks stimulus_name stimulus_id ops =
  let version_info = match stimulus_name, stimulus_id with
    | None, None -> None
    | Some name, _ -> ops.iter_lines_accu "stimuli" (extract_stimulus_versions_by_name name) None
    | _, Some id -> ops.iter_lines_accu "stimuli" (extract_stimulus_versions_by_id id) None
  in
  let stimulus_info = match version_info with
    | None -> None
    | Some (stimulus_id, min_version, max_version) ->
       let suites = ops.iter_lines_accu "stimuli_suites" (extract_stimulus_params stimulus_id) []
       and compressions = ops.iter_lines_accu "stimuli_compressions" (extract_stimulus_params stimulus_id) []
       and extensions = ops.iter_lines_accu "stimuli_extensions" (extract_stimulus_params stimulus_id) [] in
       Some (stimulus_id, min_version, max_version, suites, compressions, extensions)
  in
  match stimulus_info with
  | None ->
     let always_true _ = true in
     None, (always_true, always_true, always_true, always_true)
  | Some (stimulus_id, min_version, max_version, suites, compressions, extensions) ->
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
     Some stimulus_id, (is_version_compatible, is_suite_compatible, is_compression_compatible, are_extensions_compatible)
