#!/bin/bash

OUT_DIR="$1"
ANSWER_DUMP="$2"
TRUSTED_CA="$3"

error () {
      echo "Error: $1" >&2
      echo "Usage: maestro OUT_DIR ANSWER_DUMP TRUSTED_CA"
      exit 1
}


[ -d "$OUT_DIR" ] || mkdir "$OUT_DIR" &> /dev/null || error "Unable to create \"$OUT_DIR\" output directory."
[ -f "$ANSWER_DUMP" ] || error "Answer dump \"$ANSWER_DUMP\" does not seem to be a regular file."
which piatto > /dev/null || error "piatto executable can not be found."
[ -f "$TRUSTED_CA" ] || error "Trusted CA \"$TRUSTED_CA\" does not seem to exist."

if openssl x509 < "$TRUSTED_CA" &> /dev/null; then
   PEM_OR_DER="--pem"
else
   PEM_OR_DER="--der"
fi


echo -n "Extracting CAs..."
if piatto --ca-bundle "$OUT_DIR/cas.bundle" extract-cas "$ANSWER_DUMP" 2> /dev/null; then
   echo " OK"
else
   echo " NOK"
   exit 1
fi


echo -n "Preparing CSV files..."
if piatto --ca-bundle "$OUT_DIR/cas.bundle" -o "$OUT_DIR/csv" "$PEM_OR_DER" --ca "$TRUSTED_CA" dump2csv "$ANSWER_DUMP" 2> /dev/null; then
   echo " OK"
else
   echo " NOK"
   exit 1
fi


echo -n "Injecting data into the database..."
(cat <<EOF
create table answers(
       campaign int,
       ip text,
       name text,
       chain_hash text,
       primary key (campaign, ip, name)
);

create table chains(
       hash text,
       position int,
       cert_hash text,
       primary key (hash, position)
);

create table certs(
       hash text primary key,
       version integer,
       serial text,
       subject_hash text,
       issuer_hash text,
       notbefore text,
       notafter text,
       key_type text,
       rsa_modulus text,
       rsa_exponent text,
       isCA integer
);

create table dns(
       hash text primary key,
       name text
);

create table names(
       cert_hash text,
       type text,
       name text,
       primary key (cert_hash, type, name)
);

create table built_chains(
       chain_hash text,
       built_chain_number int,
       grade text,
       complete int,
       trusted int,
       ordered int,
       primary key (chain_hash, built_chain_number)
);

create table built_links(
       chain_hash text,
       built_chain_number int,
       position_in_chain int,
       position_in_msg int,
       cert_hash text,
       primary key (chain_hash, built_chain_number, position_in_chain)
);

create table unused_certs(
       chain_hash text,
       built_chain_number int,
       position_in_msg int,
       cert_hash text,
       primary key (chain_hash, built_chain_number, position_in_msg)
);

create table links (
       issuer_hash text,
       subject_hash text,
       primary key (issuer_hash, subject_hash)
);



.mode list
.separator :
.import answers.csv answers
.import chains.csv chains
.import certs.csv certs
.import dns.csv dns
.import names.csv names
.import built_chains.csv built_chains
.import built_links.csv built_links
.import unused_certs.csv unused_certs
.import links.csv links




create table transitive_links (
       issuer_hash text,
       subject_hash text,
       distance int,
       primary key (issuer_hash, subject_hash)
);

insert into transitive_links
  select issuer_hash, subject_hash, 0 from links
  where issuer_hash = subject_hash;

insert into transitive_links
  select issuer_hash, subject_hash, 1 from links
  where issuer_hash != subject_hash;


insert or ignore into transitive_links
  select tl1.issuer_hash, tl2.subject_hash, tl1.distance + tl2.distance
  from transitive_links tl1, transitive_links tl2
  where tl1.subject_hash = tl2.issuer_hash;

insert or ignore into transitive_links
  select tl1.issuer_hash, tl2.subject_hash, tl1.distance + tl2.distance
  from transitive_links tl1, transitive_links tl2
  where tl1.subject_hash = tl2.issuer_hash;

insert or ignore into transitive_links
  select tl1.issuer_hash, tl2.subject_hash, tl1.distance + tl2.distance
  from transitive_links tl1, transitive_links tl2
  where tl1.subject_hash = tl2.issuer_hash;

insert or ignore into transitive_links
  select tl1.issuer_hash, tl2.subject_hash, tl1.distance + tl2.distance
  from transitive_links tl1, transitive_links tl2
  where tl1.subject_hash = tl2.issuer_hash;

insert or ignore into transitive_links
  select tl1.issuer_hash, tl2.subject_hash, tl1.distance + tl2.distance
  from transitive_links tl1, transitive_links tl2
  where tl1.subject_hash = tl2.issuer_hash;

insert or ignore into transitive_links
  select tl1.issuer_hash, tl2.subject_hash, tl1.distance + tl2.distance
  from transitive_links tl1, transitive_links tl2
  where tl1.subject_hash = tl2.issuer_hash;

select count(*) from transitive_links;

insert or ignore into transitive_links
  select tl1.issuer_hash, tl2.subject_hash, tl1.distance + tl2.distance
  from transitive_links tl1, transitive_links tl2
  where tl1.subject_hash = tl2.issuer_hash;

select count(*) from transitive_links;
EOF
) | { cd "$OUT_DIR/csv"; sqlite3 "../db.sql" &> /dev/null; }
echo " OK"

