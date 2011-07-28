
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
	$(top_builddir)/p11-kit/libp11-kit-testable.la \
        $(LTLIBINTL)

ptr_array_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la \
        $(LTLIBINTL)

conf_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la \
        $(LTLIBINTL)

uri_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la \
        $(LTLIBINTL)

pin_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la \
        $(LTLIBINTL)

check-am:
	./hash-test
	./ptr-array-test
	./conf-test
	./uri-test
	./pin-test

EXTRA_DIST = \
	cutest \
	files
