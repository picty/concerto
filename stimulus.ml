open Parsifal
open TlsEnums
open Tls
open Ssl2


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
        List.map int_of_ciphersuite ch.ssl2_client_cipher_specs, [], []

     | Some _ -> failwith "Invalid stimulus: this SSLv2 Record is not a valid ClientHello"
                          
     | None -> failwith "Invalid stimulus: this is neither an SSLv2 nor TLS ClientHello"
