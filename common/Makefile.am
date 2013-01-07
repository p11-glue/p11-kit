NULL =

SUBDIRS = . tests

incdir = $(includedir)/p11-kit-1/p11-kit

inc_HEADERS = \
	pkcs11.h \
	$(NULL)

noinst_LTLIBRARIES = \
	libp11-compat.la \
	libp11-library.la \
	$(NULL)

libp11_compat_la_SOURCES = \
	compat.c compat.h \
	$(NULL)

libp11_library_la_SOURCES = \
	attrs.c attrs.h \
	array.c array.h \
	debug.c debug.h \
	dict.c dict.h \
	library.c library.h \
	pkcs11.h pkcs11x.h \
	$(NULL)
