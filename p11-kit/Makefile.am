NULL =

INCLUDES = \
	-I$(top_srcdir) \
	-DP11_KIT_FUTURE_UNSTABLE_API \
	-DP11_SYSTEM_CONFIG_FILE=\""$(p11_system_config_file)"\" \
	-DP11_SYSTEM_CONFIG_MODULES=\""$(p11_system_config_modules)"\" \
	-DP11_USER_CONFIG_FILE=\""$(p11_user_config_file)"\" \
	-DP11_USER_CONFIG_MODULES=\""$(p11_user_config_modules)"\" \
	-DP11_MODULE_PATH=\""$(p11_module_path)"\" \
	$(NULL)

incdir = $(includedir)/p11-kit-1/p11-kit

inc_HEADERS = \
	p11-kit.h \
	pin.h \
	uri.h \
	pkcs11.h

MODULE_SRCS = \
	util.c util.h \
	compat.c compat.h \
	conf.c conf.h \
	debug.c debug.h \
	hashmap.c hashmap.h \
	modules.c \
	pin.c \
	proxy.c \
	private.h \
	ptr-array.c ptr-array.h \
	messages.c \
	uri.c \
	$(inc_HEADERS)

lib_LTLIBRARIES = \
	libp11-kit.la

noinst_LTLIBRARIES = \
	libp11-kit-testable.la

libp11_kit_la_LDFLAGS = \
	-no-undefined \
	-version-info $(P11KIT_LT_RELEASE) \
	-export-symbols-regex '^C_GetFunctionList|^p11_kit_'

libp11_kit_la_SOURCES = $(MODULE_SRCS)

libp11_kit_la_LIBADD = $(LTLIBINTL)

libp11_kit_testable_la_LDFLAGS = \
	-no-undefined

libp11_kit_testable_la_SOURCES = $(MODULE_SRCS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = p11-kit-1.pc

exampledir = $(p11_system_config)
example_DATA = pkcs11.conf.example

EXTRA_DIST = \
	p11-kit-1.pc.in \
	pkcs11.conf.example.in

# Proxy module is actually same as library, so install a link
install-exec-hook:
	$(LN_S) -f `readlink $(DESTDIR)$(libdir)/libp11-kit.so` $(DESTDIR)$(libdir)/p11-kit-proxy.so
