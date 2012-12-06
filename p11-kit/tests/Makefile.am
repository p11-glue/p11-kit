
include $(top_srcdir)/build/Makefile.tests

INCLUDES = \
	-I$(top_srcdir) \
	-I$(srcdir)/.. \
	-I$(top_srcdir)/common \
	$(CUTEST_CFLAGS)

LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la \
	$(CUTEST_LIBS) \
	$(LTLIBINTL)

CHECK_PROGS = \
	progname-test \
	conf-test \
	uri-test \
	pin-test \
	test-init \
	test-modules

noinst_PROGRAMS = \
	print-messages \
	$(CHECK_PROGS)

test_init_SOURCES = test-init.c \
	mock-module.c mock-module.h
test_init_CFLAGS = $(AM_CFLAGS)

TESTS = $(CHECK_PROGS:=$(EXEEXT))

noinst_LTLIBRARIES = \
	mock-one.la \
	mock-two.la \
	mock-three.la \
	mock-four.la

mock_one_la_SOURCES = \
	mock-module.c mock-module.h \
	mock-module-ep.c

mock_one_la_LIBADD = \
	$(top_builddir)/p11-kit/libp11-kit-compat.la

mock_one_la_LDFLAGS = \
	-module -avoid-version -rpath /nowhere \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

mock_two_la_SOURCES = $(mock_one_la_SOURCES)
mock_two_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_two_la_LIBADD = $(mock_one_la_LIBADD)

mock_three_la_SOURCES = $(mock_one_la_SOURCES)
mock_three_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_three_la_LIBADD = $(mock_one_la_LIBADD)

mock_four_la_SOURCES = $(mock_one_la_SOURCES)
mock_four_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_four_la_LIBADD = $(mock_one_la_LIBADD)

EXTRA_DIST = \
	files
