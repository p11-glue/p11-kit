
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/p11-kit \
	-I$(srcdir)/cutest \
	-DSRCDIR=\"$(srcdir)\" \
	-DP11_KIT_FUTURE_UNSTABLE_API

noinst_PROGRAMS = \
	hash-test \
	ptr-array-test \
	conf-test \
	uri-test \
	pin-test

hash_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la

ptr_array_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la

conf_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la

uri_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la

pin_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la

check-am:
	./hash-test
	./ptr-array-test
	./conf-test
	./uri-test
	./pin-test

EXTRA_DIST = \
	cutest \
	files