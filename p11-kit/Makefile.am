
incdir = $(includedir)/p11-kit-1/p11-kit

inc_HEADERS = \
	p11-kit.h \
	uri.h \
	pkcs11.h

MODULE_SRCS = \
	conf.c conf.h \
	debug.c debug.h \
	hash.c hash.h \
	util.c util.h \
	modules.c \
	proxy.c \
	private.h \
	messages.c \
	uri.c \
	$(inc_HEADERS)

lib_LTLIBRARIES = \
	libp11-kit.la

noinst_LTLIBRARIES = \
	libp11-kit-testable.la

libp11_kit_la_LDFLAGS = \
	-no-undefined -export-symbols-regex '^C_GetFunctionList|^p11_kit_'

libp11_kit_la_SOURCES = $(MODULE_SRCS)

libp11_kit_testable_la_LDFLAGS = \
	-no-undefined

libp11_kit_testable_la_SOURCES = $(MODULE_SRCS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = p11-kit-1.pc

EXTRA_DIST = \
	p11-kit-1.pc.in