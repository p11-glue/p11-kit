
noinst_LTLIBRARIES += \
	libtrust-testable.la \
	libtrust-data.la

libtrust_data_la_SOURCES = \
	trust/asn1.c trust/asn1.h \
	trust/basic.asn trust/basic.asn.h \
	trust/base64.c trust/base64.h \
	trust/pem.c trust/pem.h \
	trust/pkix.asn trust/pkix.asn.h \
	trust/oid.c trust/oid.h \
	trust/openssl.asn trust/openssl.asn.h \
	trust/utf8.c trust/utf8.h \
	trust/x509.c trust/x509.h \
	$(NULL)

libtrust_data_la_CFLAGS = \
	$(LIBTASN1_CFLAGS)

libtrust_data_la_LIBADD = \
	$(LIBTASN1_LIBS) \
	$(NULL)

TRUST_SRCS = \
	trust/builder.c trust/builder.h \
	trust/digest.c trust/digest.h \
	trust/index.c trust/index.h \
	trust/parser.c trust/parser.h \
	trust/persist.c trust/persist.h \
	trust/module.c trust/module.h \
	trust/save.c trust/save.h \
	trust/session.c trust/session.h \
	trust/token.c trust/token.h \
	trust/types.h \
	$(NULL)

configdir = $(p11_package_config_modules)
config_DATA = trust/p11-kit-trust.module

moduledir = $(p11_module_path)
module_LTLIBRARIES = \
	p11-kit-trust.la

p11_kit_trust_la_CFLAGS = \
	$(LIBTASN1_CFLAGS)

p11_kit_trust_la_LIBADD = \
	libtrust-data.la \
	libp11-library.la \
	libp11-common.la \
	$(LIBTASN1_LIBS) \
	$(HASH_LIBS) \
	$(NULL)

p11_kit_trust_la_LDFLAGS = \
	-no-undefined -module -avoid-version \
	-version-info $(P11KIT_LT_RELEASE) \
	-export-symbols-regex 'C_GetFunctionList' \
	$(NULL)

p11_kit_trust_la_SOURCES = $(TRUST_SRCS)

libtrust_testable_la_LDFLAGS = \
	-no-undefined

libtrust_testable_la_SOURCES = $(TRUST_SRCS)

libtrust_testable_la_CFLAGS = \
	$(LIBTASN1_CFLAGS)

libtrust_testable_la_LIBADD = \
	$(LIBTASN1_LIBS)

bin_PROGRAMS += trust/trust

trust_trust_LDADD = \
	libtrust-data.la \
	libp11-kit.la \
	libp11-common.la \
	libp11-tool.la \
	$(LTLIBINTL) \
	$(LIBTASN1_LIBS) \
	$(HASH_LIBS) \
	$(NULL)

trust_trust_CFLAGS = \
	-DP11_KIT_FUTURE_UNSTABLE_API \
	$(LIBTASN1_CFLAGS) \
	$(NULL)

trust_trust_SOURCES = \
	trust/anchor.c trust/anchor.h \
	trust/parser.c trust/parser.h \
	trust/persist.c trust/persist.h \
	trust/digest.c trust/digest.h \
	trust/enumerate.c trust/enumerate.h \
	trust/extract.c trust/extract.h \
	trust/extract-jks.c \
	trust/extract-openssl.c \
	trust/extract-pem.c \
	trust/extract-cer.c \
	trust/list.c trust/list.h \
	trust/openssl.asn trust/openssl.asn.h \
	trust/save.c trust/save.h \
	trust/trust.c \
	$(NULL)

externaldir = $(privatedir)
external_SCRIPTS = \
	trust/trust-extract-compat

EXTRA_DIST += \
	trust/p11-kit-trust.module

asn:
	asn1Parser -o $(srcdir)/trust/pkix.asn.h $(srcdir)/trust/pkix.asn
	asn1Parser -o $(srcdir)/trust/openssl.asn.h $(srcdir)/trust/openssl.asn
	asn1Parser -o $(srcdir)/trust/basic.asn.h $(srcdir)/trust/basic.asn

# Tests ----------------------------------------------------------------

trust_CFLAGS = \
        $(LIBTASN1_CFLAGS) \
	$(NULL)

trust_LIBS = \
	libtrust-testable.la \
	libtrust-data.la \
	libtrust-test.la \
	libp11-kit.la \
	libp11-library.la \
	libp11-test.la \
	libp11-common.la \
	$(LIBTASN1_LIBS) \
	$(HASH_LIBS) \
	$(NULL)

noinst_LTLIBRARIES += \
	libtrust-test.la

libtrust_test_la_SOURCES = \
	trust/test-trust.c trust/test-trust.h \
	trust/digest.c \
	$(NULL)

CHECK_PROGS += \
	test-digest \
	test-asn1 \
	test-base64 \
	test-pem \
	test-oid \
	test-utf8 \
	test-x509 \
	test-persist \
	test-index \
	test-parser \
	test-builder \
	test-token \
	test-module \
	test-save \
	test-enumerate \
	test-cer \
	test-bundle \
	test-openssl \
	$(NULL)

test_asn1_SOURCES = trust/test-asn1.c
test_asn1_LDADD = $(trust_LIBS)
test_asn1_CFLAGS = $(trust_CFLAGS)

test_base64_SOURCES = trust/test-base64.c
test_base64_LDADD = $(trust_LIBS)
test_base64_CFLAGS = $(trust_CFLAGS)

test_builder_SOURCES = trust/test-builder.c
test_builder_LDADD = $(trust_LIBS)
test_builder_CFLAGS = $(trust_CFLAGS)

test_bundle_SOURCES = trust/test-bundle.c
test_bundle_LDADD = $(trust_LIBS)
test_bundle_CFLAGS = $(trust_CFLAGS)

test_cer_SOURCES = trust/test-cer.c
test_cer_LDADD = $(trust_LIBS)
test_cer_CFLAGS = $(trust_CFLAGS)

test_digest_SOURCES = trust/test-digest.c
test_digest_LDADD = $(trust_LIBS)
test_digest_CFLAGS = $(trust_CFLAGS)

test_enumerate_SOURCES = trust/test-enumerate.c
test_enumerate_LDADD = $(trust_LIBS)
test_enumerate_CFLAGS = $(trust_CFLAGS)

test_index_SOURCES = trust/test-index.c
test_index_LDADD = $(trust_LIBS)
test_index_CFLAGS = $(trust_CFLAGS)

test_module_SOURCES = trust/test-module.c
test_module_LDADD = $(trust_LIBS)
test_module_CFLAGS = $(trust_CFLAGS)

test_oid_SOURCES = trust/test-oid.c
test_oid_LDADD = $(trust_LIBS)
test_oid_CFLAGS = $(trust_CFLAGS)

test_openssl_SOURCES = trust/test-openssl.c
test_openssl_LDADD = $(trust_LIBS)
test_openssl_CFLAGS = $(trust_CFLAGS)

test_parser_SOURCES = trust/test-parser.c
test_parser_LDADD = $(trust_LIBS)
test_parser_CFLAGS = $(trust_CFLAGS)

test_pem_SOURCES = trust/test-pem.c
test_pem_LDADD = $(trust_LIBS)

test_persist_SOURCES = trust/test-persist.c
test_persist_LDADD = $(trust_LIBS)

test_save_SOURCES = trust/test-save.c
test_save_LDADD = $(trust_LIBS)

test_token_SOURCES = trust/test-token.c
test_token_LDADD = $(trust_LIBS)
test_token_CFLAGS = $(trust_CFLAGS)

test_utf8_SOURCES = trust/test-utf8.c
test_utf8_LDADD = $(trust_LIBS)

test_x509_SOURCES = trust/test-x509.c
test_x509_LDADD = $(trust_LIBS)
test_x509_CFLAGS = $(trust_CFLAGS)

noinst_PROGRAMS += \
	frob-pow \
	frob-token \
	frob-nss-trust \
	frob-cert \
	frob-bc \
	frob-ku \
	frob-eku \
	frob-ext \
	frob-oid \
	$(NULL)

frob_bc_SOURCES = trust/frob-bc.c
frob_bc_LDADD = $(trust_LIBS)
frob_bc_CFLAGS = $(trust_CFLAGS)

frob_cert_SOURCES = trust/frob-cert.c
frob_cert_LDADD = $(trust_LIBS)
frob_cert_CFLAGS = $(trust_CFLAGS)

frob_eku_SOURCES = trust/frob-eku.c
frob_eku_LDADD = $(trust_LIBS)
frob_eku_CFLAGS = $(trust_CFLAGS)

frob_ext_SOURCES = trust/frob-ext.c
frob_ext_LDADD = $(trust_LIBS)
frob_ext_CFLAGS = $(trust_CFLAGS)

frob_ku_SOURCES = trust/frob-ku.c
frob_ku_LDADD = $(trust_LIBS)
frob_ku_CFLAGS = $(trust_CFLAGS)

frob_nss_trust_SOURCES = trust/frob-nss-trust.c
frob_nss_trust_LDADD = \
	libp11-common.la \
	libp11-kit.la \
	$(HASH_LIBS) \
	$(NULL)

frob_oid_SOURCES = trust/frob-oid.c
frob_oid_LDADD = $(trust_LIBS)
frob_oid_CFLAGS = $(trust_CFLAGS)

frob_pow_SOURCES = trust/frob-pow.c
frob_pow_LDADD = $(trust_LIBS)
frob_pow_CFLAGS = $(trust_CFLAGS)

frob_token_SOURCES = trust/frob-token.c
frob_token_LDADD = $(trust_LIBS)
frob_token_CFLAGS = $(trust_CFLAGS)

noinst_SCRIPTS += trust/test-extract

installcheck-local:
	sh $(builddir)/trust/test-extract

EXTRA_DIST += \
	trust/input \
	trust/fixtures \
	$(NULL)
