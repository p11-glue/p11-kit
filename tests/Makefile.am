
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/module \
	-Icutest

noinst_PROGRAMS = \
	hash-test

hash_test_SOURCES = \
	hash-test.c

hash_test_LDADD = \
	$(top_builddir)/module/libp11-kit-testable.la

check-am:
	./hash-test
