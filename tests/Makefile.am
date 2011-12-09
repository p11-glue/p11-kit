
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

test_init_SOURCES = \
	test-init.c \
	mock-module.c mock-module.h

TESTS = $(CHECK_PROGS:=$(EXEEXT))

EXTRA_DIST = \
	cutest \
	files
