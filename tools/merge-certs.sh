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
            xx=$(echo -n $certname | cut -b 1-2)
            yy=$(echo -n $certname | cut -b 3-4)
            if [ -f "$dest/$xx/$yy/$certname" ]; then
                #diff "$dest/$certname" "$cert" || error "$dest/$certname and $cert should be identical!"
                ( mv "$cert" "$cert.bak" && ln "$dest/$xx/$yy/$certname" "$cert" && rm "$cert.bak" ) || error "Error while handling $dest/$xx/$yy/$certname and $cert."
            else
                mkdir -p "$dest/$xx/$yy"
                ln "$cert" "$dest/$xx/$yy/$certname"
            fi
        fi
    done
    shift
done
