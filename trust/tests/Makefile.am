
include $(top_srcdir)/build/Makefile.tests

COMMON = $(top_srcdir)/common
TRUST = $(top_srcdir)/trust

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(srcdir)/.. \
	-I$(top_srcdir)/p11-kit \
	-I$(COMMON) \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DP11_KIT_FUTURE_UNSTABLE_API \
	$(LIBTASN1_CFLAGS) \
	$(TEST_CFLAGS) \
	$(NULL)

noinst_LTLIBRARIES = \
	libtrust-test.la

libtrust_test_la_SOURCES = \
	test-trust.c test-trust.h \
	$(TRUST)/digest.c

LDADD = \
	$(top_builddir)/trust/libtrust-testable.la \
	$(top_builddir)/trust/libtrust-data.la \
	$(builddir)/libtrust-test.la \
	$(top_builddir)/p11-kit/libp11-kit.la \
	$(top_builddir)/common/libp11-library.la \
	$(top_builddir)/common/libp11-test.la \
	$(top_builddir)/common/libp11-common.la \
	$(LIBTASN1_LIBS) \
	$(HASH_LIBS) \
	$(NULL)

CHECK_PROGS = \
	test-digest \
	test-persist \
	test-index \
	test-parser \
	test-builder \
	test-token \
	test-module \
	test-save \
	test-extract \
	test-cer \
	test-bundle \
	test-openssl \
	test-asn1 \
	test-base64 \
	test-pem \
	test-oid \
	test-utf8 \
	test-x509 \
	$(NULL)

noinst_PROGRAMS = \
	frob-pow \
	frob-token \
	frob-nss-trust \
	frob-cert \
	frob-ku \
	frob-eku \
	frob-ext \
	frob-cert \
	frob-oid \
	$(CHECK_PROGS)

frob_nss_trust_LDADD = \
	$(top_builddir)/common/libp11-common.la \
	$(top_builddir)/p11-kit/libp11-kit.la \
	$(HASH_LIBS) \
	$(NULL)

TESTS = $(CHECK_PROGS)

EXTRA_DIST = \
	input \
	files \
	$(NULL)

TEST_RUNNER = libtool --mode=execute

test_save_SOURCES = \
	test-save.c \
	$(TRUST)/save.c \
	$(NULL)

test_extract_SOURCES = \
	test-extract.c \
	$(TRUST)/extract-info.c \
	$(NULL)

test_cer_SOURCES = \
	test-cer.c \
	$(TRUST)/extract-info.c \
	$(TRUST)/extract-cer.c \
	$(TRUST)/save.c \
	$(NULL)

test_bundle_SOURCES = \
	test-bundle.c \
	$(TRUST)/extract-info.c \
	$(TRUST)/extract-pem.c \
	$(TRUST)/save.c \
	$(NULL)

test_openssl_SOURCES = \
	test-openssl.c \
	$(TRUST)/extract-info.c \
	$(TRUST)/extract-openssl.c \
	$(TRUST)/save.c \
	$(NULL)
