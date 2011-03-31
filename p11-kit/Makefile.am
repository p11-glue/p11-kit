
INCLUDES = \
	-DP11_KIT_API_SUBJECT_TO_CHANGE

incdir = $(includedir)/p11-kit

inc_HEADERS = \
	p11-kit.h \
	p11-kit-uri.h \
	pkcs11.h

MODULE_SRCS = \
	conf.c conf.h \
	hash.c hash.h \
	util.c util.h \
	p11-kit-lib.c \
	p11-kit-proxy.c \
	p11-kit-private.h \
	p11-kit-messages.c \
	p11-kit-uri.c \
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
pkgconfig_DATA = p11-kit.pc

EXTRA_DIST = \
	p11-kit.pc.in