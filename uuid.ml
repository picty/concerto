let compute_uuid namespace name =
  let h = CryptoUtil.sha1sum (namespace ^ name) in
  let int64_of_str s offset =
    let chars = [
      Int64.of_int (int_of_char h.[offset]);
      Int64.of_int (int_of_char h.[offset + 1]);
      Int64.of_int (int_of_char h.[offset + 2]);
      Int64.of_int (int_of_char h.[offset + 3]);
      Int64.of_int (int_of_char h.[offset + 4]);
      Int64.of_int (int_of_char h.[offset + 5]);
      Int64.of_int (int_of_char h.[offset + 6]);
      Int64.of_int (int_of_char h.[offset + 7]);
    ] in
    List.fold_left (fun accu x -> Int64.logor (Int64.shift_left accu 8) x) 0L chars
  in
  let uuid_hi = int64_of_str h 0
  and uuid_lo = int64_of_str h 8 in
  let real_uuid_hi = Int64.logor (Int64.logand uuid_hi 0xffff_ffff_ffff_0fffL) 0x0000_0000_0000_5000L
  and real_uuid_lo = Int64.logor (Int64.logand uuid_lo 0x3fff_ffff_ffff_ffffL) 0x8000_0000_0000_0000L
  in real_uuid_hi, real_uuid_lo

let binstring_of_uuid (hi, lo) =
  let str_of_int64 s offset i =
    s.[offset] <- char_of_int (Int64.to_int (Int64.logand (Int64.shift_right_logical i 56) 0xffL));
    s.[offset + 1] <- char_of_int (Int64.to_int (Int64.logand (Int64.shift_right_logical i 48) 0xffL));
    s.[offset + 2] <- char_of_int (Int64.to_int (Int64.logand (Int64.shift_right_logical i 40) 0xffL));
    s.[offset + 3] <- char_of_int (Int64.to_int (Int64.logand (Int64.shift_right_logical i 32) 0xffL));
    s.[offset + 4] <- char_of_int (Int64.to_int (Int64.logand (Int64.shift_right_logical i 24) 0xffL));
    s.[offset + 5] <- char_of_int (Int64.to_int (Int64.logand (Int64.shift_right_logical i 16) 0xffL));
    s.[offset + 6] <- char_of_int (Int64.to_int (Int64.logand (Int64.shift_right_logical i 8) 0xffL));
    s.[offset + 7] <- char_of_int (Int64.to_int (Int64.logand i 0xffL));
  in
  let res = String.make 16 ' ' in
  str_of_int64 res 0 hi;
  str_of_int64 res 8 lo;
  res

let pretty_print_uuid uuid =
  let s = Parsifal.hexdump (binstring_of_uuid uuid) in
  (String.sub s 0 8) ^ "-" ^
    (String.sub s 8 4) ^ "-" ^
    (String.sub s 12 4) ^ "-" ^
    (String.sub s 16 4) ^ "-" ^
    (String.sub s 20 12)
