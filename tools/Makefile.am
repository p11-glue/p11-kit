
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/p11-kit \
	-DSRCDIR=\"$(srcdir)\"

bin_PROGRAMS = \
	p11-kit

p11_kit_SOURCES = \
	compat.c compat.h \
	p11-kit.c

p11_kit_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit.la \
	$(LTLIBINTL)
