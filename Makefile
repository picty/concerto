TARGETS = listCSVFiles writeLine dumpFile readFile \
	listRawTypes listRawPrefixes listRawByPrefix listRawByType \
	mergeDirs mergeRawFiles \
	testUuid testJson \
	injectAnswerDump injectZGrabResults injectStimulus \
	inject listV1certs parseCerts \
	prepareLinks stripPossibleLinks checkLinks \
	computeComponents buildChains \
	extractCertdata flagTrust rateChains \
	extractDrownCerts \
	computeStats \
	computeBehaviorStats compareAnswerTypes \
	computeChainsStats \
	filterDataDir parseCrls

TARGETS_BYTE = $(foreach t,$(TARGETS),$t.byte)

TARGETS_NATIVE = $(foreach t,$(TARGETS),$t.native)

CFLAGS = -cflags -safe-string,-w,+a-4-9-31-41-44-58,-warn-error,+a

all:
	ocamlbuild -use-ocamlfind $(CFLAGS) $(TARGETS_NATIVE)
	for i in $(TARGETS); do rm -f $$i; ln -s $$i.native $$i; done

byte:
	ocamlbuild -use-ocamlfind $(CFLAGS) $(TARGETS_BYTE)

clean:
	ocamlbuild -clean
	rm -f $(TARGETS) _build
