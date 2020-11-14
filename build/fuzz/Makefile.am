fuzz_targets = build/fuzz/rpc_fuzzer
check_PROGRAMS += $(fuzz_targets)
.PHONY: fuzz
fuzz: $(fuzz_targets)

build_fuzz_rpc_fuzzer_SOURCES = build/fuzz/rpc_fuzzer.c build/fuzz/fuzz.h build/fuzz/main.c

build_fuzz_rpc_fuzzer_LDADD = libp11-kit-testable.la libp11-test.la libp11-common.la
