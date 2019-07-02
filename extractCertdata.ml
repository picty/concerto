open Str
open Getopt
open Base64
open BasePTypes

type action = All | Server | Email | Code | Distrusted
let action = ref All
let set_action value = TrivialFun (fun () -> action := value)
let verbose = ref false
let set_verbose value = TrivialFun (fun () -> verbose := value)
let output = ref ""
let output_dir = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "Show this help message";
  mkopt (Some 'a') "all" (set_action All) "Dumps all trusted certs (default)";
  mkopt (Some 's') "server" (set_action Server) "Dumps only certs trusted for servers";
  mkopt (Some 'e') "email" (set_action Email) "Dumps only certs trusted for emails";
  mkopt (Some 'c') "code" (set_action Code) "Dumps only certs trusted for code";
  mkopt (Some 'd') "distrusted" (set_action Distrusted) "Dumps only distrusted certs";
  mkopt (Some 'v') "verbose" (set_verbose true) "Display more information";
  mkopt (Some 'o') "output" (StringVal output) "Output certificates to this file";
  mkopt None "output-dir" (StringVal output_dir) "Output certificates to this directory (DER format)";
]

module LabelSet = Set.Make(String)


let dump_cert out label value =
  let buf = POutput.create () in
  let dump = dump_base64_container (HeaderInList ["CERTIFICATE"]) dump_binstring in
  dump buf value;
  POutput.add_char buf '\n';
  POutput.output_buffer out buf;
  if !verbose then Printf.fprintf stderr "Dumped certificate %s\n" label

let normalize s =
  let n = String.length s in
  let res =
    if n > 2 && s.[0] = '"' && s.[n-1] = '"'
    then Bytes.of_string (String.sub s 1 (n-2))
    else Bytes.of_string s
  in
  for i = 0 to (Bytes.length res) - 1 do
    let c = Bytes.get res i in
    let x = int_of_char c in
    if (x < 33) || (x >= 128) || (c = '/')
    then Bytes.set res i '_'
  done;
  Bytes.to_string res

let dump_cert_in_separate_file dir label value =
  let f = open_out (dir ^ "/" ^ (normalize label) ^ ".der") in
  output_string f value;
  close_out f;
  if !verbose then Printf.fprintf stderr "Dumped certificate %s\n" label


let read_octal line =
  let values = Str.split (regexp "\\") line in
  let octal_values = List.map (fun x -> int_of_string ("0o" ^ x)) values in
  let char_values = List.map Char.chr octal_values in
  let buf = Buffer.create (List.length char_values) in
  let rec join = function
    | [] -> buf
    | c::rst -> Buffer.add_char buf c; join rst
  in
  Buffer.contents (join char_values)


type state = Trust | Cert

let split_line line = Str.bounded_split (regexp "[ \t]+") line 3

let handle_file dump_cert_fun filename =
  let chan = open_in filename in
  let label = ref "" in
  let label_set = ref LabelSet.empty in
  let certs = Hashtbl.create 256  in
  let state = ref None in
  try
    while true do
      let line = input_line chan in
      match !state, split_line line with
      | None, "CKA_CLASS"::"CK_OBJECT_CLASS"::"CKO_CERTIFICATE"::[] ->
        state := Some Cert
      | None, "CKA_CLASS"::"CK_OBJECT_CLASS"::"CKO_NSS_TRUST"::[] ->
        state := Some Trust
      | Some _, "CKA_LABEL"::"UTF8"::escaped_label::[] ->
        label := escaped_label;
        if !action = All then label_set := (LabelSet.add !label !label_set)
      | Some Cert, "CKA_VALUE"::"MULTILINE_OCTAL"::[] ->
        let rec read_octal_until_end chan init =
          let line = input_line chan in
          if line <> "END" then
            read_octal_until_end chan (init ^ (read_octal line))
          else
            init
        in
        Hashtbl.add certs !label (read_octal_until_end chan "")
      | Some Trust, "CKA_TRUST_SERVER_AUTH"::"CK_TRUST"::"CKT_NSS_TRUSTED_DELEGATOR"::[] ->
        if !action = Server then label_set := (LabelSet.add !label !label_set)
      | Some Trust, "CKA_TRUST_EMAIL_PROTECTION"::"CK_TRUST"::"CKT_NSS_TRUSTED_DELEGATOR"::[] ->
        if !action = Email then label_set := (LabelSet.add !label !label_set)
      | Some Trust, "CKA_TRUST_CODE_SIGNING"::"CK_TRUST"::"CKT_NSS_TRUSTED_DELEGATOR"::[] ->
        if !action = Code then label_set := (LabelSet.add !label !label_set)
      | Some Trust, _::"CK_TRUST"::"CKT_NSS_NOT_TRUSTED"::[] ->
        label_set := if !action = Distrusted then (LabelSet.add !label !label_set)
        else (LabelSet.remove !label !label_set)
      | Some _, [] ->
        state := None
      | _ -> ()
    done
  with End_of_file -> ();
  Hashtbl.iter (fun l c ->
    if LabelSet.mem l !label_set then dump_cert_fun l c) certs;
  let total = Hashtbl.fold (fun l _ c -> if LabelSet.mem l !label_set then c + 1 else c) certs 0 in
  Printf.fprintf stderr "Dumped %d certificates\n" total


let () =
  let filenames = parse_args ~progname:"certdata" options Sys.argv in
  let dump_cert_fun = match !output, !output_dir with
    | "", "" -> dump_cert stdout
    | output_file, "" -> dump_cert (open_out output_file)
    | "", output_dir ->
       begin
         try Unix.mkdir output_dir 0o755
         with _ -> ()
       end;
       dump_cert_in_separate_file output_dir
    | _, _ -> usage "certdata" options (Some "Please choose either an output file or an output dir")
  in
  List.iter (handle_file dump_cert_fun) filenames
