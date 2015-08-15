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
       echo " OK"
    else
        echo " NOK"
        exit 1
    fi
}

[ -d "$DATA_DIR" ] || mkdir "$DATA_DIR" &> /dev/null || error "Unable to create \"$DATA_DIR\" output directory."
[ -f "$ANSWER_DUMP" ] || error "Answer dump \"$ANSWER_DUMP\" does not seem to be a regular file."
# which piatto > /dev/null || error "piatto executable can not be found."


echo -n "Extracting answers..."
"$BIN_DIR/injectAnswerDump" -d "$DATA_DIR" "$ANSWER_DUMP" 2> /dev/null
handle_ret_code

echo -n "Parsing certs..."
"$BIN_DIR/parseCerts" -d "$DATA_DIR" $( for i in $(seq 0 255); do printf "%2.2x " $i; done ) 2> /dev/null
handle_ret_code

echo -n "Preparing possible links..."
"$BIN_DIR/prepareLinks" -d "$DATA_DIR" 2> /dev/null
handle_ret_code

echo -n "Checking links..."
"$BIN_DIR/checkLinks" -d "$DATA_DIR" 2> /dev/null
handle_ret_code
rm -f "$DATA_DIR"/possible_links.csv

echo -n "Building chains..."
"$BIN_DIR/buildChains" -d "$DATA_DIR" 2> /dev/null
handle_ret_code

if [ "$*" = "" ]; then
    touch "$DATA_DIR/trusted_certs.csv" "$DATA_DIR/trusted_chains.csv"
    touch "$DATA_DIR/rated_chains.csv"
else
    echo -n "Flag trusted certs..."
    "$BIN_DIR/flagTrust" -d "$DATA_DIR" --der "$@" 2> /dev/null
    handle_ret_code

    echo -n "Rate chains..."
    "$BIN_DIR/rateChains" -d "$DATA_DIR" 2> /dev/null
    handle_ret_code
fi

echo -n "Injecting data into the database..."
cat "$BIN_DIR/db.txt" | { cd "$DATA_DIR"; sqlite3 "db.sql" &> /dev/null; }
handle_ret_code
