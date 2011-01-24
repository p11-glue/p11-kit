
INCLUDES = \
	-DPKCS11_MODULE_PATH=\"$(PKCS11_MODULE_PATH)\"

MODULE_SRCS = \
	p11-kit.c \
	hash.c hash.h

lib_LTLIBRARIES = p11-kit.la

p11_kit_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

p11_kit_la_SOURCES = $(MODULE_SRCS)

EXTRA_DIST = \
	pkcs11.h