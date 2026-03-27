fuzz_targets = fuzz/rpc_fuzzer fuzz/uri_fuzzer fuzz/conf_fuzzer
check_PROGRAMS += $(fuzz_targets)
fuzz: $(fuzz_targets)

fuzz_rpc_fuzzer_SOURCES = fuzz/rpc_fuzzer.c fuzz/fuzz.h fuzz/main.c

fuzz_rpc_fuzzer_LDADD = libp11-kit-testable.la libp11-test.la libp11-common.la

fuzz_uri_fuzzer_SOURCES = fuzz/uri_fuzzer.c fuzz/fuzz.h fuzz/main.c

fuzz_uri_fuzzer_LDADD = libp11-kit-testable.la libp11-test.la libp11-common.la

fuzz_conf_fuzzer_SOURCES = fuzz/conf_fuzzer.c fuzz/fuzz.h fuzz/main.c

fuzz_conf_fuzzer_LDADD = libp11-kit-testable.la libp11-test.la libp11-common.la

EXTRA_DIST += fuzz/meson.build

# Build fuzzers that only need libp11-kit libraries
oss-fuzz: libp11-kit-testable.la libp11-test.la libp11-common.la libp11-library.la libp11-asn1.la libtrust-testable.la libtrust-data.la
	if test "$$OUT" != ""; then \
	for src_file in $(top_srcdir)/fuzz/*_fuzzer.c; do \
	fuzzer=$$(basename $$src_file .c); \
	$$CC $$CFLAGS -I. -I$(top_srcdir) -I$(top_srcdir)/common \
	-I$(top_builddir)/trust $(LIBTASN1_CFLAGS) \
	-c $(top_srcdir)"/fuzz/$${fuzzer}.c" -o "$${fuzzer}.o" ; \
	$$CXX $$CXXFLAGS "$${fuzzer}.o" -o "$$OUT/$${fuzzer}" \
	.libs/libtrust-testable.a .libs/libtrust-data.a \
	.libs/libp11-kit-testable.a .libs/libp11-test.a \
	.libs/libp11-asn1.a .libs/libp11-library.a .libs/libp11-common.a \
	-lffi -ldl -lpthread $(LIBTASN1_LIBS) $(HASH_LIBS) \
	$${LIB_FUZZING_ENGINE} || exit 1; \
	done; \
	fi

.PHONY: fuzz oss-fuzz
