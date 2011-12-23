
INCLUDES = \
	-I$(top_srcdir) \
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
	conf-test \
	uri-test \
	pin-test \
	test-init

noinst_PROGRAMS = \
	print-messages \
	$(CHECK_PROGS)

cutestfiles = cutest/CuTest.c cutest/CuTest.h

conf_test_SOURCES = conf-test.c $(cutestfiles)
hash_test_SOURCES = hash-test.c $(cutestfiles)
pin_test_SOURCES = pin-test.c $(cutestfiles)
ptr_array_test_SOURCES = ptr-array-test.c $(cutestfiles)
test_init_SOURCES = \
	test-init.c \
	mock-module.c mock-module.h $(cutestfiles)

uri_test_SOURCES = uri-test.c $(cutestfiles)

TESTS = $(CHECK_PROGS:=$(EXEEXT))

EXTRA_DIST = \
	cutest \
	files
