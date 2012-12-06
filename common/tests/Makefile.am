
include $(top_srcdir)/build/Makefile.tests

NULL =

COMMON = $(top_srcdir)/common

INCLUDES = \
	-I$(top_srcdir) \
	-I$(srcdir)/.. \
	-I$(COMMON) \
	$(CUTEST_CFLAGS)

LDADD = $(CUTEST_LIBS)

CHECK_PROGS = \
	test-dict \
	test-array \
	$(NULL)

test_dict_SOURCES = \
	test-dict.c \
	$(COMMON)/dict.c

test_array_SOURCES = \
	test-array.c \
	$(COMMON)/array.c

noinst_PROGRAMS = \
	$(CHECK_PROGS)

TESTS = $(CHECK_PROGS:=$(EXEEXT))
