# configurable section
TARGETS = listCSVFiles writeLine dumpFile readFile \
	listRawTypes listRawPrefixes listRawByPrefix listRawByType \
	mergeDirs mergeRawFiles \
	testUuid testJson \
	injectAnswerDump injectZGrabResults injectStimulus \
	inject listV1certs parseCerts \
	prepareLinks stripPossibleLinks checkLinks \
	computeComponents buildChains \
	extract-certdata flagTrust rateChains \
	computeStats computeBehaviorStats \
	computeChainsStats

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

testUuid_SRCS := uuid.ml testUuid.ml
testJson_SRCS := testJson.ml

injectAnswerDump_SRCS := fileOps.ml stimulus.ml injectAnswerDump.ml
injectZGrabResults_SRCS := fileOps.ml stimulus.ml injectZGrabResults.ml
injectStimulus_SRCS := stimulus.ml fileOps.ml injectStimulus.ml
inject_SRCS := fileOps.ml inject.ml
listV1certs_SRCS := fileOps.ml listV1certs.ml
parseCerts_SRCS := fileOps.ml parseCerts.ml
prepareLinks_SRCS := fileOps.ml prepareLinks.ml
stripPossibleLinks_SRCS := fileOps.ml stripPossibleLinks.ml
checkLinks_SRCS := fileOps.ml checkLinks.ml
computeComponents_SRCS := fileOps.ml computeComponents.ml
buildChains_SRCS := fileOps.ml buildChains.ml
extract-certdata_SRCS := extract-certdata.ml
flagTrust_SRCS := fileOps.ml flagTrust.ml
rateChains_SRCS := fileOps.ml rateChains.ml

computeStats_SRCS := concertoUtils.ml fileOps.ml statOps.ml computeStats.ml
computeBehaviorStats_SRCS := concertoUtils.ml fileOps.ml statOps.ml computeBehaviorStats.ml
computeChainsStats_SRCS := concertoUtils.ml fileOps.ml statOps.ml computeChainsStats.ml

# comment this line if not using camlp4
# USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str calendar cryptokit \
        parsifal_syntax parsifal_core parsifal_crypto \
        parsifal_net parsifal_lwt parsifal_ssl \
        easy-format biniou yojson

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS =
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS =
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include Makefile.ocaml

