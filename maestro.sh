#!/bin/bash

BIN_DIR="$(dirname "$0")"

DATA_DIR="$1"
ANSWER_DUMP="$2"
shift 2

error () {
      echo "Error: $1" >&2
      echo "Usage: maestro OUT_DIR ANSWER_DUMP TRUSTED_CA"
      exit 1
}

handle_ret_code () {
    if [ "$?" = "0" ]; then
       echo "OK"
       echo
    else
        echo "NOK"
        exit 1
    fi
}

[ -d "$DATA_DIR" ] || mkdir "$DATA_DIR" &> /dev/null || error "Unable to create \"$DATA_DIR\" output directory."
[ -f "$ANSWER_DUMP" ] || error "Answer dump \"$ANSWER_DUMP\" does not seem to be a regular file."
# which piatto > /dev/null || error "piatto executable can not be found."


echo "= Extracting answers ="
time "$BIN_DIR/injectAnswerDump" -d "$DATA_DIR" "$ANSWER_DUMP" 2> /dev/null
handle_ret_code

echo "= Parsing certs ="
time "$BIN_DIR/parseCerts" -d "$DATA_DIR" $( for i in $(seq 0 255); do printf "%2.2x " $i; done ) 2> /dev/null
handle_ret_code

echo "= Preparing possible links ="
time "$BIN_DIR/prepareLinks" -d "$DATA_DIR" 2> /dev/null
handle_ret_code

echo "= Checking links ="
time "$BIN_DIR/checkLinks" -d "$DATA_DIR" 2> /dev/null
handle_ret_code
rm -f "$DATA_DIR"/possible_links.csv

echo "= Building chains ="
time "$BIN_DIR/buildChains" -d "$DATA_DIR" 2> /dev/null
handle_ret_code

if [ "$*" = "" ]; then
    touch "$DATA_DIR/trusted_certs.csv" "$DATA_DIR/trusted_chains.csv"
    touch "$DATA_DIR/rated_chains.csv"
else
    echo "= Flag trusted certs "
    time "$BIN_DIR/flagTrust" -d "$DATA_DIR" --der "$@" 2> /dev/null
    handle_ret_code

    echo "= Rate chains ="
    time "$BIN_DIR/rateChains" -d "$DATA_DIR" 2> /dev/null
    handle_ret_code
fi

echo "Injecting data into the database..."
cat "$BIN_DIR/db.txt" | { cd "$DATA_DIR"; time sqlite3 "db.sql" &> /dev/null; }
handle_ret_code
