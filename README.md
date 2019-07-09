README
======

Concerto is a set of tools to analyse SSL/TLS datasets.  In
particular, it can extract, analyse and browse certificates and
chains.


Extraction and analysis tools
-----------------------------

All the programs presented in this section are described (with their
associated tables) in the doc/documentation.png image (obtained with
"make -C doc" on a system with the dot tools).

injectAnswerDump takes dump files and extract answer information
(answer type, TLS version and ciphersuite, certificate chain hash), as
well as chains and certificates.

inject allows to directly inject binary files (e.g. trusted
certificates).

parseCerts parses all certificates to extract relevant fields in some
tables (certs, dns and names).

prepareLinks extracts all the possible links between certificates,
using only information present in certs table.

checkLinks checks the signature of possibleLinks to produce the table
of the real links.

buildChains tries and build all possible chains from the available
data.

flagTrust recursively flags trusted certs, starting from roots.

rateChains grades the built chains, using trust information when
available.

maestro.sh is a script proposing to call the previous programs in the
right order to provide a computed data-dir ready to use with piccolo.


More analysis tools (WIP)
-------------------------

computeComponents is a work-in-progress tool to split certificates in
connex components. This would be the first step leading to the
transitive closure of the signed-by relation.

extractDrownCerts flags with the "@drown" tag all server certificates
used in an SSLv2 exchange recorded in the answers.csv table.


Certificate store handlers
--------------------------

extract-certdata extracts trusted roots from NSS certdata.txt file.

extract-ev-certdata.py extracts EV tags from NSS source.


Statistical tools
-----------------

computeStats is a generic tool to extract statistics on answer types,
versions and ciphersuites. It can take trust flags into account.

computeChainsStats presents statistics regarding chain quality.

computeBehaviorStats is a work-in-progress to produce statistics
concerning multiple campaigns at the same time. The idea is to
correlate information related to a given IP contacted using different
stimuli.


Low-level tools
---------------

To manipulate the data, the data-dir contains "tables" (currently
implemented as CSV files) and "packs" (files used to store binary
data). The following programs allow to operate the data-dir at a
low-level:

  * listCSVFiles
  * writeLine
  * dumpFile
  * readFile
  * listRawTypes
  * listRawPrefixes
  * listRawByPrefix
  * listRawByType


Step-by-step analysis of a list of domain names
-----------------------------------------------

### Data collection

  1. Write the list of hosts you want to probe in a hosts.txt file:

    DNS:www.google.com
    DNS:github.com

  2. Launch the probe_server program from Parsifal.  It is possible to
  adapt the stimuli you want to test (versions, ciphersuites,
  extensions).  The following snippet uses a TLS 1.2 ClientHello with
  all known ciphersuites.

    probe_server probe2dump --hosts-file=hosts.txt -o campaign.ad2 --campaign 1


### Data injection and analysis

  1. Prepare your certificate trust store, i.e. a directory containing
  DER X.509 files.  You can do this using
  /usr/share/ca-certificates/mozilla/ on a Debian system:

    $ mkdir store
    $ for i in /usr/share/ca-certificates/mozilla/*; do
        openssl enc -d -base64 < "$i" > "store/$(basename $i)"
      done

  2. Launch the maestro.sh script to parse and enrich the data:

    $(CONCERTO_DIR)/maestro.sh  -D store -d datadir -v campaign.ad2


  3. The datadir now contains .csv files and the corresponding data
  has been imported in an SQLite database.


### Data exploration

  1. Start piccolo on your data:

    $(CONCERT_DIR)/piccolo.py datadir/db.sql

  2. Browse the web application

    firefox http://127.0.0.1:5000
    
