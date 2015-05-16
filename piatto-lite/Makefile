# configurable section
TARGETS = piatto parseCerts prepareLinks checkLinks \
	writeLine dumpFile readFile listFiles mergeRawFiles

piatto_SRCS := fileOps.ml piatto.ml
parseCerts_SRCS := fileOps.ml parseCerts.ml
prepareLinks_SRCS := fileOps.ml prepareLinks.ml
checkLinks_SRCS := fileOps.ml checkLinks.ml
writeLine_SRCS := fileOps.ml writeLine.ml
dumpFile_SRCS := fileOps.ml dumpFile.ml
readFile_SRCS := fileOps.ml readFile.ml
listFiles_SRCS := fileOps.ml listFiles.ml
mergeRawFiles_SRCS := fileOps.ml mergeRawFiles.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str calendar cryptokit \
        parsifal_syntax parsifal_core parsifal_crypto \
        parsifal_net parsifal_lwt parsifal_ssl

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../common/Makefile.ocaml

