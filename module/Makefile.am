
MODULE_SRCS = \
	conf.c conf.h \
	hash.c hash.h \
	p11-kit-lib.c \
	p11-kit-proxy.c \
	p11-kit-private.h p11-kit.h

lib_LTLIBRARIES = \
	libp11-kit.la

noinst_LTLIBRARIES = \
	libp11-kit-testable.la

libp11_kit_la_LDFLAGS = \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

libp11_kit_la_SOURCES = $(MODULE_SRCS)

libp11_kit_testable_la_LDFLAGS = \
	-no-undefined

libp11_kit_testable_la_SOURCES = $(MODULE_SRCS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = p11-kit.pc

EXTRA_DIST = \
	pkcs11.h \
	p11-kit.pc.in