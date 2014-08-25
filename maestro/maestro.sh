#!/bin/bash

OUT_DIR="$1"
ANSWER_DUMP="$2"
BIN_DIR="$3"
TRUSTED_CA="$4"
PIATTO="$BIN_DIR/piatto/piatto"

error () {
      echo "Error: $1" >&2
      echo "Usage: maestro OUT_DIR ANSWER_DUMP BIN_DIR TRUSTED_CA"
      exit 1
}


[ -d "$OUT_DIR" ] || mkdir "$OUT_DIR" &> /dev/null || error "Unable to create \"$OUT_DIR\" output directory."
[ -f "$ANSWER_DUMP" ] || error "Answer dump \"$ANSWER_DUMP\" does not seem to be a regular file."
[ -d "$BIN_DIR" ] || error "\"$BIN_DIR\" is an invalid directory."
[ -f "$PIATTO" ] || error "\"$PIATTO\" does not exist."
[ -f "$TRUSTED_CA" ] || error "Trusted CA \"$TRUSTED_CA\" does not seem to exist."

if openssl x509 < "$TRUSTED_CA" &> /dev/null; then
   PEM_OR_DER="--pem"
else
   PEM_OR_DER="--der"
fi


echo -n "Extracting CAs..."
if "$PIATTO" --ca-bundle "$OUT_DIR/cas.bundle" extract-cas "$ANSWER_DUMP" 2> /dev/null; then
   echo " OK"
else
   echo " NOK"
   exit 1
fi


echo -n "Preparing CSV files..."
if "$PIATTO" --ca-bundle "$OUT_DIR/cas.bundle" -o "$OUT_DIR/csv" "$PEM_OR_DER" --ca "$TRUSTED_CA" dump2csv "$ANSWER_DUMP" 2> /dev/null; then
   echo " OK"
else
   echo " NOK"
   exit 1
fi


echo -n "Injecting data into the database..."
cat "$BIN_DIR/chitarra/db.txt" | { cd "$OUT_DIR/csv"; sqlite3 "../db.sql" &> /dev/null; }
echo " OK"

