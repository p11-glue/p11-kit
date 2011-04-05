
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/p11-kit \
	-DSRCDIR=\"$(srcdir)\" \
	-DP11_KIT_API_SUBJECT_TO_CHANGE

bin_PROGRAMS = \
	p11-kit

p11_kit_LDADD = \
	$(top_builddir)/p11-kit/libp11-kit.la
