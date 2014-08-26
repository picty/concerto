#!/bin/bash

DATABASE="$1"
ANSWER_DUMP="$2"
CAMPAIGN="$3"

error () {
      echo "Error: $1" >&2
      echo "Usage: new-campaign.sh DATABASE ANSWER_DUMP CAMPAIGN"
      exit 1
}


[ -f "$DATABASE" ] || error "Database \"$DATABASE\" does not seem to be a regular file."
[ -n "$CAMPAIGN" ] || error "Please provide a campaign number."
which probe_server > /dev/null || error "probe_server executable can not be found."

TMP_DIR="$(mktemp -d)"
echo "Using temporary directory \"$TMP_DIR\"."

echo -n "Extracting IPs..."
(sqlite3 "$DATABASE" <<EOF
select ip from answers;
EOF
) | while read ip; do
   echo "IP: $ip";
done | sort -u | tee "$TMP_DIR/ips.txt" | wc -l | { read n_ips; echo "$n_ips IPs found"; }

echo -n "Extracting names (in answers)..."
(sqlite3 "$DATABASE" <<EOF
select name from answers;
EOF
) | while read name; do
   [ -n "$name" ] && echo "DNS: $name";
done | sort -u | tee "$TMP_DIR/names.txt" | wc -l | { read n_names; echo "$n_names names found"; }

echo -n "Extracting names (in CN and DNS)..."
(sqlite3 "$DATABASE" <<EOF
select names.name from names
join certs on certs.hash = names.cert_hash,
     chains on chains.cert_hash = certs.hash
where (names.type = "CN" or names.type = "DNS")
  and chains.position=0;
EOF
) | while read name; do
    echo "DNS: $name";
done | grep -v '*' | sed '/^DNS: [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$/d' | cat - "$TMP_DIR/names.txt" | sort -u | tee "$TMP_DIR/names2.txt" | wc -l | { read n_names; n_new_names=$(( $n_names - $(cat "$TMP_DIR/names.txt" | wc -l) )); echo "$n_new_names new names found"; }

cat "$TMP_DIR/ips.txt" "$TMP_DIR/names2.txt" | sort -R > "$TMP_DIR/hosts.txt"


probe_server --hosts-file "$TMP_DIR/hosts.txt" --campaign "$CAMPAIGN" -d1 --max-parallel-requests=20 \
   -V TLSv1.0 \
   --clear-suites \
   -A TLS_RSA_WITH_RC4_128_SHA \
   -A TLS_RSA_WITH_RC4_128_MD5 \
   -A TLS_RSA_WITH_AES_256_CBC_SHA \
   -A TLS_DHE_RSA_WITH_AES_256_CBC_SHA \
   -A TLS_DHE_RSA_WITH_AES_128_CBC_SHA \
   probe2dump \
   -o "$ANSWER_DUMP"
