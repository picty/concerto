# configurable section
TARGETS = listCSVFiles writeLine dumpFile readFile \
	listRawTypes listRawPrefixes listRawByPrefix listRawByType \
	mergeDirs mergeRawFiles \
	injectAnswerDump parseCerts prepareLinks checkLinks \
	removeIsolatedCerts computeComponents buildChains \
	flagTrust rateChains \

listCSVFiles_SRCS := fileOps.ml listCSVFiles.ml
writeLine_SRCS := fileOps.ml writeLine.ml

dumpFile_SRCS := fileOps.ml dumpFile.ml
readFile_SRCS := fileOps.ml readFile.ml
listRawTypes_SRCS := fileOps.ml listRawTypes.ml
listRawPrefixes_SRCS := fileOps.ml listRawPrefixes.ml
listRawByPrefix_SRCS := fileOps.ml listRawByPrefix.ml
listRawByType_SRCS := fileOps.ml listRawByType.ml

mergeDirs_SRCS := fileOps.ml mergeDirs.ml
mergeRawFiles_SRCS := fileOps.ml mergeRawFiles.ml

injectAnswerDump_SRCS := fileOps.ml injectAnswerDump.ml
parseCerts_SRCS := fileOps.ml parseCerts.ml
prepareLinks_SRCS := fileOps.ml prepareLinks.ml
checkLinks_SRCS := fileOps.ml checkLinks.ml
removeIsolatedCerts_SRCS := fileOps.ml removeIsolatedCerts.ml
computeComponents_SRCS := fileOps.ml computeComponents.ml
buildChains_SRCS := fileOps.ml buildChains.ml
flagTrust_SRCS := fileOps.ml flagTrust.ml
rateChains_SRCS := fileOps.ml rateChains.ml

# comment this line if not using camlp4
# USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str calendar cryptokit \
        parsifal_syntax parsifal_core parsifal_crypto \
        parsifal_net parsifal_lwt parsifal_ssl

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS =
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS =
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include Makefile.ocaml

