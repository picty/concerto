#!/bin/sh

dest="$1"
shift
[ -d "$dest" ] || mkdir "$dest"

error () {
	echo "$1" >&2
	exit 1
}

while [ -d "$1" ]; do
    for cert in "$1"/*; do
	if [ -f "$cert" ]; then
            certname=$(basename $cert)
            if [ -f "$dest/$certname" ]; then
                diff "$dest/$certname" "$cert" || error "$dest/$certname and $cert should be identical!"
                rm "$cert"
                ln "$dest/$certname" "$cert"
            else
                ln "$cert" "$dest/$certname"
            fi
        fi
    done
    shift
done
