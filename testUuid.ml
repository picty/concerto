open Uuid

let namespace_DNS = "\x6b\xa7\xb8\x10\x9d\xad\x11\xd1\x80\xb4\x00\xc0\x4f\xd4\x30\xc8"
let namespace_DNS_uuid = (0x6ba7_b810_9dad_11d1L, 0x80b4_00c0_4fd4_30c8L)

let name = "www.example.org"

let expected_uuid = "74738ff5-5367-5958-9aee-98fffdcd1876"
let uuid = compute_uuid namespace_DNS name

let _ =
  Printf.printf "namespace_DNS_uuid = %s\n" (pretty_print_uuid namespace_DNS_uuid);
  Printf.printf "expected_uuid = %s\n" expected_uuid;
  Printf.printf "computed_uuid = %s\n" (pretty_print_uuid uuid)
  
