
include $(top_srcdir)/build/Makefile.decl

SUBDIRS = . tests

COMMON = $(top_srcdir)/common

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(COMMON) \
	-DSRCDIR=\"$(srcdir)\" \
	-DBINDIR=\"$(bindir)\" \
	-DPRIVATEDIR=\"$(privatedir)\" \
	-DP11_KIT_FUTURE_UNSTABLE_API \
	$(NULL)

incdir = $(includedir)/p11-kit-1/p11-kit

inc_HEADERS = \
	deprecated.h \
	iter.h \
	p11-kit.h \
	pin.h \
	uri.h \
	$(NULL)

MODULE_SRCS = \
	util.c \
	conf.c conf.h \
	iter.c \
	log.c log.h \
	modules.c modules.h \
	pkcs11.h \
	pin.c \
	pkcs11.h \
	proxy.c proxy.h \
	private.h \
	messages.c \
	rpc-message.c rpc-message.h \
	rpc-client.c rpc-server.c rpc.h \
	uri.c \
	virtual.c virtual.h \
	$(inc_HEADERS)

lib_LTLIBRARIES = \
	libp11-kit.la

libp11_kit_la_CFLAGS = \
	-DP11_SYSTEM_CONFIG_FILE=\""$(p11_system_config_file)"\" \
	-DP11_SYSTEM_CONFIG_MODULES=\""$(p11_system_config_modules)"\" \
	-DP11_PACKAGE_CONFIG_MODULES=\""$(p11_package_config_modules)"\" \
	-DP11_USER_CONFIG_FILE=\""$(p11_user_config_file)"\" \
	-DP11_USER_CONFIG_MODULES=\""$(p11_user_config_modules)"\" \
	-DP11_MODULE_PATH=\""$(p11_module_path)"\" \
	$(LIBFFI_CFLAGS) \
	$(NULL)

libp11_kit_la_LDFLAGS = \
	-no-undefined \
	-version-info $(P11KIT_LT_RELEASE) \
	-export-symbols-regex '^C_GetFunctionList|^p11_kit_'

libp11_kit_la_SOURCES = $(MODULE_SRCS)

libp11_kit_la_LIBADD = \
	$(top_builddir)/common/libp11-common.la \
	$(top_builddir)/common/libp11-library.la \
	$(LIBFFI_LIBS) \
	$(LTLIBINTL) \
	$(NULL)

noinst_LTLIBRARIES = \
	libp11-kit-testable.la

libp11_kit_testable_la_LDFLAGS = -no-undefined
libp11_kit_testable_la_SOURCES = $(MODULE_SRCS)
libp11_kit_testable_la_LIBADD = $(libp11_kit_la_LIBADD)

if OS_WIN32

libp11_kit_testable_la_CFLAGS = \
	-DP11_SYSTEM_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/tests/files/system-pkcs11.conf"\" \
	-DP11_SYSTEM_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/tests/files/system-modules/win32"\" \
	-DP11_PACKAGE_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/tests/files/package-modules/win32"\" \
	-DP11_USER_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/tests/files/user-pkcs11.conf"\" \
	-DP11_USER_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/tests/files/user-modules/win32"\" \
	-DP11_MODULE_PATH=\""$(abs_top_builddir)/p11-kit/tests/.libs"\" \
	$(LIBFFI_CFLAGS) \
	$(NULL)

else

libp11_kit_testable_la_CFLAGS = \
	-DP11_SYSTEM_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/tests/files/system-pkcs11.conf"\" \
	-DP11_SYSTEM_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/tests/files/system-modules"\" \
	-DP11_PACKAGE_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/tests/files/package-modules"\" \
	-DP11_USER_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/tests/files/user-pkcs11.conf"\" \
	-DP11_USER_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/tests/files/user-modules"\" \
	-DP11_MODULE_PATH=\""$(abs_top_builddir)/p11-kit/tests/.libs"\" \
	$(LIBFFI_CFLAGS) \
	$(NULL)

# Proxy module is actually same as library, so install a link
install-exec-hook:
	$(LN_S) -f `readlink $(DESTDIR)$(libdir)/libp11-kit.so` $(DESTDIR)$(libdir)/p11-kit-proxy.so
	$(MKDIR_P) $(DESTDIR)$(p11_package_config_modules)

endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = p11-kit-1.pc

exampledir = $(p11_system_config)
example_DATA = pkcs11.conf.example

EXTRA_DIST = \
	p11-kit-1.pc.in \
	pkcs11.conf.example.in \
	docs.h \
	$(NULL)

bin_PROGRAMS = \
	p11-kit

p11_kit_SOURCES = \
	lists.c \
	p11-kit.c \
	$(NULL)

p11_kit_CFLAGS = \
	$(NULL)

p11_kit_LDADD = \
	libp11-kit.la \
	$(top_builddir)/common/libp11-tool.la \
	$(top_builddir)/common/libp11-common.la \
	$(LTLIBINTL) \
	$(NULL)
