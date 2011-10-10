
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/p11-kit \
	-I$(srcdir)/cutest \
	-DSRCDIR=\"$(srcdir)\" \
	-DP11_KIT_FUTURE_UNSTABLE_API

LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la \
	$(LTLIBINTL)

noinst_PROGRAMS = \
	hash-test \
	ptr-array-test \
	conf-test \
	uri-test \
	pin-test \
	print-messages \
	test-init

test_init_SOURCES = \
	test-init.c \
	mock-module.c mock-module.h

check-am:
	./hash-test
	./ptr-array-test
	./conf-test
	./uri-test
	./pin-test
	./test-init

EXTRA_DIST = \
	cutest \
	files
