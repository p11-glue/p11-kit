
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/module \
	-Icutest \
	-DSRCDIR=\"$(srcdir)\"

noinst_PROGRAMS = \
	hash-test \
	conf-test

hash_test_LDADD = \
	$(top_builddir)/module/libp11-kit-testable.la

conf_test_LDADD = \
	$(top_builddir)/module/libp11-kit-testable.la

check-am:
	./hash-test
	./conf-test
