
include $(top_srcdir)/build/Makefile.tests

INCLUDES = \
	-I$(top_srcdir) \
	-I$(srcdir)/.. \
	-I$(top_srcdir)/common \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	$(TEST_CFLAGS)

noinst_LTLIBRARIES = \
	libtestdata.la

libtestdata_la_SOURCES = \
	test-trust.c test-trust.h

LDADD = \
	$(top_builddir)/trust/libtrust-testable.la \
	$(top_builddir)/common/libp11-data.la \
	$(top_builddir)/common/libp11-library.la \
	$(top_builddir)/common/libp11-test.la \
	$(top_builddir)/common/libp11-common.la \
	$(builddir)/libtestdata.la \
	$(LIBTASN1_LIBS) \
	$(CUTEST_LIBS) \
	$(NULL)

CHECK_PROGS = \
	test-persist \
	test-index \
	test-parser \
	test-builder \
	test-token \
	test-module \
	$(NULL)

noinst_PROGRAMS = \
	frob-pow \
	frob-token \
	frob-nss-trust \
	$(CHECK_PROGS)

frob_nss_trust_LDADD = \
	$(top_builddir)/common/libp11-common.la \
	$(top_builddir)/p11-kit/libp11-kit.la

TESTS = $(CHECK_PROGS)

EXTRA_DIST = \
	input \
	files \
	$(NULL)
