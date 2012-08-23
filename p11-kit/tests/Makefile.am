
include $(top_srcdir)/build/Makefile.tests

COMMON = $(top_srcdir)/common

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(srcdir)/.. \
	-I$(COMMON) \
	$(TEST_CFLAGS)

LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la \
	$(top_builddir)/common/libp11-test.la \
	$(top_builddir)/common/libp11-common.la \
	$(LTLIBINTL)

CHECK_PROGS = \
	test-progname \
	test-util \
	test-conf \
	test-uri \
	test-pin \
	test-init \
	test-modules \
	test-deprecated \
	test-proxy \
	test-iter \
	test-rpc \
	$(NULL)

if WITH_FFI

CHECK_PROGS += \
	test-virtual \
	test-managed \
	test-log \
	$(NULL)

endif

noinst_PROGRAMS = \
	print-messages \
	frob-setuid \
	$(CHECK_PROGS)

TESTS = $(CHECK_PROGS)

noinst_LTLIBRARIES = \
	mock-one.la \
	mock-two.la \
	mock-three.la \
	mock-four.la

mock_one_la_SOURCES = \
	mock-module-ep.c

mock_one_la_CFLAGS = \
	$(AM_CFLAGS)

mock_one_la_LIBADD = \
	$(top_builddir)/common/libp11-test.la \
	$(top_builddir)/common/libp11-common.la \
	$(NULL)

mock_one_la_LDFLAGS = \
	-module -avoid-version -rpath /nowhere \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

mock_two_la_SOURCES = $(mock_one_la_SOURCES)
mock_two_la_CFLAGS = $(mock_one_la_CFLAGS)
mock_two_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_two_la_LIBADD = $(mock_one_la_LIBADD)

mock_three_la_SOURCES = $(mock_one_la_SOURCES)
mock_three_la_CFLAGS = $(mock_one_la_CFLAGS)
mock_three_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_three_la_LIBADD = $(mock_one_la_LIBADD)

mock_four_la_SOURCES = $(mock_one_la_SOURCES)
mock_four_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_four_la_LIBADD = $(mock_one_la_LIBADD)

EXTRA_DIST = \
	files \
	test-mock.c \
	$(NULL)
