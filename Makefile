TARGETS = listCSVFiles writeLine dumpFile readFile \
	listRawTypes listRawPrefixes listRawByPrefix listRawByType \
	mergeDirs mergeRawFiles \
	testUuid testJson \
	injectAnswerDump injectZGrabResults injectStimulus \
	inject listV1certs parseCerts \
	prepareLinks stripPossibleLinks checkLinks \
	computeComponents buildChains \
	extract-certdata flagTrust rateChains \
	extractDrownCerts \
	computeStats \
	computeBehaviorStats compareAnswerTypes \
	computeChainsStats \
	filterDataDir

TARGETS_BYTE = $(foreach t,$(TARGETS),$t.byte)

TARGETS_NATIVE = $(foreach t,$(TARGETS),$t.native)

all:
	ocamlbuild -use-ocamlfind $(TARGETS_NATIVE)
	for i in $(TARGETS); do rm -f $$i; ln -s $$i.native $$i; done

byte:
	ocamlbuild -use-ocamlfind $(TARGETS_BYTE)

clean:
	ocamlbuild -clean
	rm -f $(TARGETS) _build
