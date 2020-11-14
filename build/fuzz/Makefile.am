fuzz_targets = build/fuzz/rpc_fuzzer
check_PROGRAMS += $(fuzz_targets)
fuzz: $(fuzz_targets)

build_fuzz_rpc_fuzzer_SOURCES = build/fuzz/rpc_fuzzer.c build/fuzz/fuzz.h build/fuzz/main.c

build_fuzz_rpc_fuzzer_LDADD = libp11-kit-testable.la libp11-test.la libp11-common.la

oss-fuzz: libp11-kit-testable.la libp11-test.la libp11-common.la
	if test "$$OUT" != ""; then \
	for src_file in $(top_srcdir)/build/fuzz/*_fuzzer.c; do \
	fuzzer=$$(basename $$src_file .c); \
	$$CC $$CFLAGS -I. -I$(top_srcdir) -I$(top_srcdir)/common \
	-c $(top_srcdir)"/build/fuzz/$${fuzzer}.c" -o "$${fuzzer}.o" ; \
	$$CXX $$CXXFLAGS "$${fuzzer}.o" -o "$$OUT/$${fuzzer}" \
	.libs/libp11-kit-testable.a .libs/libp11-test.a .libs/libp11-common.a \
	-lffi -ldl -lpthread $${LIB_FUZZING_ENGINE} || exit $?; \
	done; \
	fi

.PHONY: fuzz oss-fuzz
