
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/common \
	-I$(top_srcdir)/p11-kit \
	-I$(srcdir)/cutest \
	-DSRCDIR=\"$(srcdir)\" \
	-DP11_KIT_FUTURE_UNSTABLE_API

LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la \
	$(LTLIBINTL)

CHECK_PROGS = \
	hash-test \
	ptr-array-test \
	progname-test \
	conf-test \
	uri-test \
	pin-test \
	test-init \
	test-modules

noinst_PROGRAMS = \
	print-messages \
	$(CHECK_PROGS)

cutestfiles = cutest/CuTest.c cutest/CuTest.h

conf_test_SOURCES = conf-test.c $(cutestfiles)
hash_test_SOURCES = hash-test.c $(cutestfiles)
pin_test_SOURCES = pin-test.c $(cutestfiles)
ptr_array_test_SOURCES = ptr-array-test.c $(cutestfiles)
progname_test_SOURCES = progname-test.c $(cutestfiles)
test_init_SOURCES = test-init.c $(cutestfiles) \
	mock-module.c mock-module.h
test_init_CFLAGS = $(AM_CFLAGS)
test_modules_SOURCES = test-modules.c $(cutestfiles)

uri_test_SOURCES = uri-test.c $(cutestfiles)

TESTS = $(CHECK_PROGS:=$(EXEEXT))

noinst_LTLIBRARIES = \
	mock-one.la \
	mock-two.la \
	mock-three.la

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

EXTRA_DIST = \
	cutest \
	files
