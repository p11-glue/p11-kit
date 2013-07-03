
include $(top_srcdir)/build/Makefile.decl

SUBDIRS = . tests

COMMON = $(top_srcdir)/common

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/common \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	$(LIBTASN1_CFLAGS) \
	$(NULL)

noinst_LTLIBRARIES = \
	libtrust-testable.la \
	libtrust-data.la

libtrust_data_la_SOURCES = \
	asn1.c asn1.h \
	basic.asn basic.asn.h \
	base64.c base64.h \
	pem.c pem.h \
	pkix.asn pkix.asn.h \
	oid.c oid.h \
	openssl.asn openssl.asn.h \
	utf8.c utf8.h \
	x509.c x509.h \
	$(NULL)

MODULE_SRCS = \
	builder.c builder.h \
	index.c index.h \
	parser.c parser.h \
	persist.c persist.h \
	module.c module.h \
	session.c session.h \
	token.c token.h \
	types.h \
	$(NULL)

configdir = $(p11_package_config_modules)
config_DATA = p11-kit-trust.module

moduledir = $(p11_module_path)
module_LTLIBRARIES = \
	p11-kit-trust.la

p11_kit_trust_la_CFLAGS = \
	$(LIBTASN1_CFLAGS)

p11_kit_trust_la_LIBADD = \
	libtrust-data.la \
	$(top_builddir)/common/libp11-library.la \
	$(top_builddir)/common/libp11-common.la \
	$(LIBTASN1_LIBS) \
	$(NULL)

p11_kit_trust_la_LDFLAGS = \
	-no-undefined -module -avoid-version \
	-version-info $(P11KIT_LT_RELEASE) \
	-export-symbols-regex 'C_GetFunctionList' \
	$(NULL)

p11_kit_trust_la_SOURCES = $(MODULE_SRCS)

libtrust_testable_la_LDFLAGS = \
	-no-undefined

libtrust_testable_la_SOURCES = $(MODULE_SRCS)

bin_PROGRAMS = \
	trust

trust_LDADD = \
	libtrust-data.la \
	$(top_builddir)/p11-kit/libp11-kit.la \
	$(top_builddir)/common/libp11-common.la \
	$(top_builddir)/common/libp11-tool.la \
	$(LTLIBINTL) \
	$(LIBTASN1_LIBS) \
	$(NULL)

trust_CFLAGS = \
	-I$(top_srcdir)/p11-kit \
	-DP11_KIT_FUTURE_UNSTABLE_API \
	$(LIBTASN1_CFLAGS) \
	$(NULL)

trust_SOURCES = \
	extract.c extract.h \
	extract-info.c \
	extract-jks.c \
	extract-openssl.c \
	extract-pem.c \
	extract-cer.c \
	openssl.asn openssl.asn.h \
	save.c save.h \
	trust.c \
	$(NULL)

externaldir = $(privatedir)
external_SCRIPTS = \
	p11-kit-extract-trust

EXTRA_DIST = \
	p11-kit-trust.module

asn:
	asn1Parser -o pkix.asn.h pkix.asn
	asn1Parser -o openssl.asn.h openssl.asn
	asn1Parser -o basic.asn.h basic.asn
