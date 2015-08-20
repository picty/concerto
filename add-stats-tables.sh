#!/bin/sh

#!/bin/bash

error () {
      echo "Error: $1" >&2
      echo "Usage: add-stats-tables.sh -d OUT_DIR"
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

create table stats_answertypes(
       campaign int,
       trust_flag text,
       answer_type int,
       count int
);

create table stats_versions(
       campaign int,
       trust_flag text,
       version int,
       count int
);

create table stats_ciphersuites(
       campaign int,
       trust_flag text,
       ciphersuite int,
       count int
);



-- Import

.mode list
.separator :
.import $DATA_DIR/stats_answertypes.csv stats_answertypes
.import $DATA_DIR/stats_versions.csv stats_versions
.import $DATA_DIR/stats_ciphersuites.csv stats_ciphersuites
EOF
