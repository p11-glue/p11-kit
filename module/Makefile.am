
INCLUDES = \
	-DPKCS11_CONFIG_FILE=\"$(sysconfdir)/pkcs11.conf\" \
	-DPKCS11_CONFIG_LIBS=\"$(sysconfdir)/pkcs11/libs\"

MODULE_SRCS = \
	conf.c conf.h \
	hash.c hash.h \
	p11-kit-lib.c \
	p11-kit-proxy.c \
	p11-kit-private.h p11-kit.h

lib_LTLIBRARIES = p11-kit.la

p11_kit_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

p11_kit_la_SOURCES = $(MODULE_SRCS)

EXTRA_DIST = \
	pkcs11.h