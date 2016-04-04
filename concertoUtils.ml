module Integer = struct
  type t = int
  let compare x y = Pervasives.compare x y
end

module IntSet = Set.Make (Integer)
module StringSet = Set.Make (String)
