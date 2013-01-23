
include $(top_srcdir)/build/Makefile.tests

NULL =

EXTRA_DIST = files

if WITH_ASN1

COMMON = $(top_srcdir)/common
TOOLS = $(top_srcdir)/tools

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/p11-kit \
	-I$(srcdir)/.. \
	-I$(COMMON) \
	-DP11_KIT_FUTURE_UNSTABLE_API \
	$(CUTEST_CFLAGS)

LDADD = \
	$(top_builddir)/p11-kit/libp11-kit.la \
	$(top_builddir)/common/libp11-data.la \
	$(top_builddir)/common/libp11-library.la \
	$(top_builddir)/common/libp11-compat.la \
	$(builddir)/libtestcommon.la \
	$(LIBTASN1_LIBS) \
	$(LTLIBINTL) \
	$(CUTEST_LIBS) \
	$(NULL)

noinst_LTLIBRARIES = \
	libtestcommon.la

libtestcommon_la_SOURCES = \
	test.c test.h

CHECK_PROGS = \
	test-save \
	$(NULL)

noinst_PROGRAMS = \
	$(CHECK_PROGS)

TESTS = $(CHECK_PROGS:=$(EXEEXT))

test_save_SOURCES = \
	test-save.c \
	$(TOOLS)/save.c \
	$(NULL)

endif # WITH_ASN1
