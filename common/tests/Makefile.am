
include $(top_srcdir)/build/Makefile.tests

COMMON = $(top_srcdir)/common

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(srcdir)/.. \
	-I$(COMMON) \
	-DBUILDDIR=\"$(abs_builddir)\" \
	$(TEST_CFLAGS) \
	$(CUTEST_CFLAGS)

LDADD = \
	$(NULL)

CHECK_PROGS = \
	test-tests \
	test-compat \
	test-hash \
	test-dict \
	test-array \
	test-constants \
	test-attrs \
	test-buffer \
	test-url \
	test-path \
	test-lexer \
	$(NULL)

noinst_PROGRAMS = \
	frob-getauxval \
	$(CHECK_PROGS)

TESTS = $(CHECK_PROGS)

LDADD += \
	$(top_builddir)/common/libp11-test.la \
	$(top_builddir)/common/libp11-common.la \
	$(CUTEST_LIBS)
