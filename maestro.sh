#!/bin/bash

BIN_DIR="$(dirname "$0")"

DATA_DIR="$1"
ANSWER_DUMP="$2"
# TRUSTED_CA="$3"

error () {
      echo "Error: $1" >&2
#      echo "Usage: maestro OUT_DIR ANSWER_DUMP TRUSTED_CA"
      echo "Usage: maestro OUT_DIR ANSWER_DUMPTED_CA"
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

echo -n "Building chains..."
"$BIN_DIR/buildChains" -d "$DATA_DIR" extract-cas "$ANSWER_DUMP" 2> /dev/null
handle_ret_code

echo -n "Injecting data into the database..."
cat "$BIN_DIR/db.txt" | { cd "$DATA_DIR"; sqlite3 "db.sql" &> /dev/null; }
handle_ret_code
