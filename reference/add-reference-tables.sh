#!/bin/sh

#!/bin/bash

error () {
      echo "Error: $1" >&2
      echo "Usage: add-reference-tables.sh -d OUT_DIR"
      exit 1
}


BIN_DIR="$(dirname "$0")"
DATA_DIR=
VERBOSE=

while getopts "d:v" option; do
    case "$option" in
        d)
            DATA_DIR="$OPTARG"
            ;;
        v)
            VERBOSE=1
            ;;
        *)
            error "Invalid option \"$option\""
            ;;
    esac
done

[ -d "$DATA_DIR" ] || mkdir "$DATA_DIR" &> /dev/null || error "Unable to create \"$DATA_DIR\" output directory."

shift $(($OPTIND - 1))


sqlite3 "$DATA_DIR/stats-db.sql" <<EOF
-- Table creation

create table tls_ciphersuites(
       ciphersuite int,
       name text,
       kx text,
       au text,
       enc text,
       enc_mode text,
       enc_keysize int,
       mac text,
       mac_keysize,
       prf text,
       rfc int,
       export int,
       minversion text,
       maxversion text,
       kind text,
       pfs int,
       primary key (ciphersuite)
);

create table tls_versions(
       version int,
       name text
);

create table answer_types(
       answer_type int,
       name text
);

create table chain_quality(
       quality int,
       name text
);


-- Import

.mode list
.separator :
.import $BIN_DIR/enriched-ciphersuites.csv tls_ciphersuites
.import $BIN_DIR/versions.csv tls_versions
.import $BIN_DIR/answer_types.csv answer_types
.import $BIN_DIR/chain_quality.csv chain_quality
EOF
