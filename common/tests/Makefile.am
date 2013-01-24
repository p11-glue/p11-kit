
include $(top_srcdir)/build/Makefile.tests

NULL =

COMMON = $(top_srcdir)/common

INCLUDES = \
	-I$(top_srcdir) \
	-I$(srcdir)/.. \
	-I$(COMMON) \
	$(CUTEST_CFLAGS)

LDADD = \
	$(top_builddir)/common/libp11-library.la \
	$(top_builddir)/common/libp11-compat.la \
	$(top_builddir)/common/libp11-data.la \
	$(CUTEST_LIBS) \
	$(NULL)

CHECK_PROGS = \
	test-checksum \
	test-dict \
	test-array \
	test-attrs \
	test-buffer \
	$(NULL)

noinst_PROGRAMS = \
	$(CHECK_PROGS)

TESTS = $(CHECK_PROGS:=$(EXEEXT))
