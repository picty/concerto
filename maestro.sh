#!/bin/bash

error () {
      echo "Error: $1" >&2
      echo "Usage: maestro -d OUT_DIR [-D TRUSTED_CA_DIR|-C TRUSTED_CA] ANSWER_DUMPS"
      exit 1
}


BIN_DIR="$(dirname "$0")"
DATA_DIR=
TRUSTED_CAS=
VERBOSE=

while getopts "d:C:D:v" option; do
    case "$option" in
        d)
            DATA_DIR="$OPTARG"
            ;;
        D)
            TRUSTED_CAS="$(ls -1 "$OPTARG"/*) $TRUSTED_CAS"
            ;;
        C)
            TRUSTED_CAS="$OPTARG $TRUSTED_CAS"
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



if [ -n "$VERBOSE" ]; then
    echo "DATA_DIR=$DATA_DIR"
    echo -n "TRUSTED_CAS="
    for i in $TRUSTED_CAS; do echo -n "$i "; done
    echo
    echo -n "ANSWER_DUMPS ($#)="
    for i in "$@"; do echo -n "$i "; done
    echo    
fi



handle_ret_code () {
    if [ "$?" = "0" ]; then
       echo "OK"
       echo
    else
        echo "NOK"
        exit 1
    fi
}



echo "= Extracting answers ="
time "$BIN_DIR/injectAnswerDump" -d "$DATA_DIR" "$@" 2> /dev/null
handle_ret_code

if [ "$TRUSTED_CAS" != "" ]; then
    echo "= Injecting certs ="
    "$BIN_DIR/inject" -d "$DATA_DIR" -t certs $TRUSTED_CAS
    handle_ret_code
fi

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

if [ "$TRUSTED_CAS" = "" ]; then
    touch "$DATA_DIR/trusted_certs.csv" "$DATA_DIR/trusted_chains.csv"
    touch "$DATA_DIR/rated_chains.csv"
else
    echo "= Flaging trusted certs "
    time "$BIN_DIR/flagTrust" -d "$DATA_DIR" --der $TRUSTED_CAS 2> /dev/null
    handle_ret_code

    echo "= Rating chains ="
    time "$BIN_DIR/rateChains" -d "$DATA_DIR" 2> /dev/null
    handle_ret_code
fi

echo "= Injecting data into the database ="
mkdir "$DATA_DIR/tmp"
export TMPDIR="$DATA_DIR/tmp"
cat "$BIN_DIR/db.txt" | { cd "$DATA_DIR"; time sqlite3 "db.sql" &> /dev/null; }
handle_ret_code
