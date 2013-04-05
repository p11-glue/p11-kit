
include $(top_srcdir)/build/Makefile.tests

EXTRA_DIST = files

if WITH_ASN1

COMMON = $(top_srcdir)/common
TOOLS = $(top_srcdir)/tools

TEST_RUNNER = libtool --mode=execute

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/p11-kit \
	-I$(srcdir)/.. \
	-I$(COMMON) \
	-DP11_KIT_FUTURE_UNSTABLE_API \
	$(LIBTASN1_CFLAGS) \
	$(TEST_CFLAGS) \
	$(NULL)

LDADD = \
	$(top_builddir)/p11-kit/libp11-kit.la \
	$(top_builddir)/common/libp11-data.la \
	$(top_builddir)/common/libp11-test.la \
	$(top_builddir)/common/libp11-common.la \
	$(builddir)/libtestcommon.la \
	$(LIBTASN1_LIBS) \
	$(LTLIBINTL) \
	$(CUTEST_LIBS) \
	$(NULL)

noinst_LTLIBRARIES = \
	libtestcommon.la

libtestcommon_la_SOURCES = \
	test-tools.c test-tools.h

CHECK_PROGS = \
	test-save \
	test-extract \
	test-x509 \
	test-pem \
	test-openssl \
	$(NULL)

noinst_PROGRAMS = \
	$(CHECK_PROGS)

TESTS = $(CHECK_PROGS)

test_save_SOURCES = \
	test-save.c \
	$(TOOLS)/save.c \
	$(NULL)

test_extract_SOURCES = \
	test-extract.c \
	$(TOOLS)/extract-info.c \
	$(NULL)

test_x509_SOURCES = \
	test-x509.c \
	$(TOOLS)/extract-info.c \
	$(TOOLS)/extract-x509.c \
	$(TOOLS)/save.c \
	$(NULL)

test_pem_SOURCES = \
	test-pem.c \
	$(TOOLS)/extract-info.c \
	$(TOOLS)/extract-pem.c \
	$(TOOLS)/save.c \
	$(NULL)

test_openssl_SOURCES = \
	test-openssl.c \
	$(TOOLS)/extract-info.c \
	$(TOOLS)/extract-openssl.c \
	$(TOOLS)/save.c \
	$(NULL)

endif # WITH_ASN1
