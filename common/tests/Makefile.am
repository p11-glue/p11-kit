
include $(top_srcdir)/build/Makefile.tests

COMMON = $(top_srcdir)/common

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(srcdir)/.. \
	-I$(COMMON) \
	$(TEST_CFLAGS)

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
	test-url \
	test-path \
	test-lexer \
	$(NULL)

noinst_PROGRAMS = \
	$(CHECK_PROGS)

TESTS = $(CHECK_PROGS)

LDADD += \
	$(top_builddir)/common/libp11-test.la \
	$(top_builddir)/common/libp11-common.la \
	$(CUTEST_LIBS)
