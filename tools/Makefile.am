NULL =

COMMON = $(top_srcdir)/common

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/common \
	-I$(top_srcdir)/p11-kit \
	-DSRCDIR=\"$(srcdir)\" \
	-DPKGDATADIR=\"$(pkgdatadir)\" \
	-DP11_KIT_FUTURE_UNSTABLE_API \
	$(NULL)

bin_PROGRAMS = \
	p11-kit

p11_kit_SOURCES = \
	list.c \
	tool.c tool.h \
	$(NULL)

p11_kit_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit.la \
	$(top_builddir)/common/libp11-library.la \
	$(top_builddir)/common/libp11-compat.la \
	$(LTLIBINTL) \
	$(NULL)
