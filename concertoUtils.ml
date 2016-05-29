module Integer = struct
  type t = int
  let compare x y = Pervasives.compare x y
end

module ChainId = struct
  type t = string * int
  let compare x y = Pervasives.compare x y
end

module IntSet = Set.Make (Integer)
module StringSet = Set.Make (String)
module ChainIdSet = Set.Make (ChainId)


type chain_quality =
  | Incomplete
  | Transvalid
  | Unordered
  | RFCCompliant

let int_of_chain_quality = function
  | Incomplete -> 0
  | Transvalid -> 1
  | Unordered -> 2
  | RFCCompliant -> 3

let char_of_chain_quality = function
  | Incomplete -> 'I'
  | Transvalid -> 'T'
  | Unordered -> 'U'
  | RFCCompliant -> 'C'

let compare_chain_quality q1 q2 = compare (int_of_chain_quality q1) (int_of_chain_quality q2)

let chain_quality_of_details = function
  | false, _, _, _, _, _ -> Incomplete
  | true, true, 0, 0, _, _ -> RFCCompliant
  | true, true, _, 0, _, _
  | true, false, _, 0, _, _ -> Unordered
  | true, _, _, _, _, _ -> Transvalid


type key_typesize =
  | NoKeyType
  | MostlyRSA of int | RSA of int
  | DSA | DH | ECDSA | Unknown

let string_of_key_typesize = function
  | NoKeyType | Unknown -> ""
  | MostlyRSA n -> "rsa" ^ (string_of_int n)
  | RSA n -> "RSA" ^ (string_of_int n)
  | DSA -> "DSA"
  | DH -> "DH"
  | ECDSA -> "ECDSA"

let key_typesize_of_string = function
  | "" -> Unknown
  | "DSA" -> DSA
  | "ECDSA" -> ECDSA
  | "DH" -> DH
  | s ->
     let len = String.length s in
     if len > 3 then begin
       if String.sub s 0 3 = "RSA"
       then RSA (int_of_string (String.sub s 3 (len - 3)))
       else if String.sub s 0 3 = "rsa"
       then MostlyRSA (int_of_string (String.sub s 3 (len - 3)))
       else failwith "Internal inconsistency"
     end else failwith "Internal inconsistency"
