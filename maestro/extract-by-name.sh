#!/bin/sh

DATABASE="$1"
ANSWER_DUMP="$2"
NAME="$3"
OUT_DIR="$4"
TRUSTED_CA="$5"

error () {
      echo "Error: $1" >&2
      echo "Usage: maestro DATABASE ANSWER_DUMP NAME OUT_DIR TRUSTED_CA"
      exit 1
}


[ -f "$DATABASE" ] || error "Database \"$DATABASE\" does not seem to be a regular file."
[ -f "$ANSWER_DUMP" ] || error "Answer dump \"$ANSWER_DUMP\" does not seem to be a regular file."
[ -n "$NAME" ] || error "Please specify a NAME (and do not play with SQL injections :-p)."
[ -n "$( echo "$NAME" | tr -d -- '-_a-zA-Z 0-9.%' )" ] && error "NAME contains strange characters."
[ -d "$OUT_DIR" ] || mkdir "$OUT_DIR" &> /dev/null || error "Unable to create \"$OUT_DIR\" output directory."
[ -f "$TRUSTED_CA" ] || error "Trusted CA \"$TRUSTED_CA\" does not seem to exist."
which mapAnswers > /dev/null || error "mapAnswers executable can not be found."
which maestro.sh > /dev/null || error "maestro.sh executable can not be found."
which piccolo.py > /dev/null || error "piccolo executable can not be found."

(sqlite3 "$1" << EOF
select ip from answers
join built_chains on built_chains.chain_hash = answers.chain_hash,
     built_links on built_links.chain_hash = built_chains.chain_hash
                and built_links.built_chain_number = built_chains.built_chain_number,
     certs on built_links.cert_hash = certs.hash,
     dns on certs.subject_hash = dns.hash
where dns.name LIKE "%$NAME%"
group by ip

union select ip from answers
join chains on chains.hash = answers.chain_hash,
     certs on chains.cert_hash = certs.hash,
     dns on certs.subject_hash = dns.hash
where dns.name LIKE "%$NAME%"
group by ip;

EOF
) > "$OUT_DIR/ips.txt"

mapAnswers -2 --filter-ips "$OUT_DIR/ips.txt" -D "$ANSWER_DUMP" > "$OUT_DIR/$NAME.dump"

maestro.sh "$OUT_DIR" "$OUT_DIR/$NAME.dump" "$TRUSTED_CA"

piccolo.py "$OUT_DIR/db.sql" &

sleep 3

cd "$OUT_DIR/"
wget -mk "http://localhost:5000/chains/by-subject-in-chain/$NAME"
cd -

echo "Don't forget to kill piccolo!"
