
include $(top_srcdir)/build/Makefile.decl

SUBDIRS = . tests

COMMON = $(top_srcdir)/common

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/common \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	$(LIBTASN1_CFLAGS) \
	$(NULL)

MODULE_SRCS = \
	builder.c builder.h \
	index.c index.h \
	parser.c parser.h \
	persist.c persist.h \
	module.c module.h \
	session.c session.h \
	token.c token.h \
	$(NULL)

configdir = $(p11_package_config_modules)
config_DATA = p11-kit-trust.module

moduledir = $(p11_module_path)
module_LTLIBRARIES = \
	p11-kit-trust.la

p11_kit_trust_la_CFLAGS = \
	$(LIBTASN1_CFLAGS)

p11_kit_trust_la_LIBADD = \
	$(top_builddir)/common/libp11-data.la \
	$(top_builddir)/common/libp11-library.la \
	$(top_builddir)/common/libp11-compat.la \
	$(LIBTASN1_LIBS) \
	$(NULL)

p11_kit_trust_la_LDFLAGS = \
	-no-undefined -module -avoid-version \
	-version-info $(P11KIT_LT_RELEASE) \
	-export-symbols-regex 'C_GetFunctionList' \
	$(NULL)

p11_kit_trust_la_SOURCES = $(MODULE_SRCS)

noinst_LTLIBRARIES = \
	libtrust-testable.la

libtrust_testable_la_LDFLAGS = \
	-no-undefined

libtrust_testable_la_SOURCES = $(MODULE_SRCS)

EXTRA_DIST = \
	p11-kit-trust.module
