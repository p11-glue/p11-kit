
include $(top_srcdir)/build/Makefile.tests

COMMON = $(top_srcdir)/common

INCLUDES = \
	-I$(top_srcdir) \
	-I$(srcdir)/.. \
	-I$(COMMON) \
	$(CUTEST_CFLAGS)

LDADD = \
	$(NULL)

CHECK_PROGS = \
	test-compat \
	test-hash \
	test-dict \
	test-array \
	test-constants \
	test-attrs \
	test-buffer \
	test-lexer \
	test-url \
	$(NULL)

noinst_PROGRAMS = \
	$(CHECK_PROGS)

if WITH_ASN1

LDADD += \
	$(top_builddir)/common/libp11-data.la \
	$(LIBTASN1_LIBS) \
	$(NULL)

INCLUDES += \
	$(LIBTASN1_CFLAGS) \
	$(NULL)

CHECK_PROGS += \
	test-asn1 \
	test-base64 \
	test-pem \
	test-oid \
	test-utf8 \
	test-x509 \
	$(NULL)

noinst_PROGRAMS += \
	frob-cert \
	frob-ku \
	frob-eku \
	frob-cert \
	frob-oid \
	$(NULL)

endif # WITH_ASN1

TESTS = $(CHECK_PROGS)

LDADD += \
	$(top_builddir)/common/libp11-library.la \
	$(top_builddir)/common/libp11-compat.la \
	$(CUTEST_LIBS)
