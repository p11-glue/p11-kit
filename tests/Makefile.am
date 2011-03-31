
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/p11-kit \
	-Icutest \
	-DSRCDIR=\"$(srcdir)\" \
	-DP11_KIT_API_SUBJECT_TO_CHANGE

noinst_PROGRAMS = \
	hash-test \
	conf-test \
	uri-test

hash_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la

conf_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la

uri_test_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit-testable.la

check-am:
	./hash-test
	./conf-test
	./uri-test