
include $(top_srcdir)/build/Makefile.tests

NULL =

COMMON = $(top_srcdir)/common

INCLUDES = \
	-I$(top_srcdir) \
	-I$(srcdir)/.. \
	-I$(COMMON) \
	$(CUTEST_CFLAGS)

LDADD = \
	$(NULL)

CHECK_PROGS = \
	test-dict \
	test-array \
	test-attrs \
	test-buffer \
	$(NULL)

noinst_PROGRAMS = \
	$(CHECK_PROGS)

TESTS = $(CHECK_PROGS:=$(EXEEXT))

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
	test-checksum \
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

LDADD += \
	$(top_builddir)/common/libp11-library.la \
	$(top_builddir)/common/libp11-compat.la \
	$(CUTEST_LIBS)
