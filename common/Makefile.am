
include $(top_srcdir)/build/Makefile.decl

SUBDIRS = . tests

incdir = $(includedir)/p11-kit-1/p11-kit

inc_HEADERS = \
	pkcs11.h \
	$(NULL)

noinst_LTLIBRARIES = \
	libp11-common.la \
	libp11-library.la \
	libp11-test.la \
	$(NULL)

libp11_common_la_SOURCES = \
	argv.c argv.h \
	attrs.c attrs.h \
	array.c array.h \
	buffer.c buffer.h \
	compat.c compat.h \
	constants.c constants.h \
	debug.c debug.h \
	dict.c dict.h \
	hash.c hash.h \
	lexer.c lexer.h \
	message.c message.h \
	path.c path.h \
	pkcs11.h pkcs11x.h \
	url.c url.h \
	$(NULL)

libp11_library_la_SOURCES = \
	library.c library.h \
	$(NULL)

libp11_test_la_SOURCES = \
	mock.c mock.h \
	test.c test.h \
	$(NULL)

if WITH_ASN1

noinst_LTLIBRARIES += \
	libp11-data.la \
	$(NULL)

libp11_data_la_SOURCES = \
	asn1.c asn1.h \
	basic.asn basic.asn.h \
	base64.c base64.h \
	oid.c oid.h \
	openssl.asn openssl.asn.h \
	pem.c pem.h \
	pkix.asn pkix.asn.h \
	utf8.c utf8.h \
	x509.c x509.h \
	$(NULL)

libp11_data_la_CFLAGS = \
	$(LIBTASN1_CFLAGS)

asn:
	asn1Parser -o pkix.asn.h pkix.asn
	asn1Parser -o openssl.asn.h openssl.asn
	asn1Parser -o basic.asn.h basic.asn

endif # WITH_ASN1
