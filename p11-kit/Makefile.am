
inc_HEADERS += \
	p11-kit/deprecated.h \
	p11-kit/iter.h \
	p11-kit/p11-kit.h \
	p11-kit/pin.h \
	p11-kit/remote.h \
	p11-kit/uri.h \
	$(NULL)

COMMON_SRCS = \
	p11-kit/util.c \
	p11-kit/conf.c p11-kit/conf.h \
	p11-kit/iter.c \
	p11-kit/log.c p11-kit/log.h \
	p11-kit/filter.c p11-kit/filter.h \
	p11-kit/modules.c p11-kit/modules.h \
	p11-kit/pkcs11.h \
	p11-kit/pin.c \
	p11-kit/pkcs11.h \
	p11-kit/private.h \
	p11-kit/messages.c \
	p11-kit/rpc-transport.c p11-kit/rpc.h \
	p11-kit/rpc-message.c p11-kit/rpc-message.h \
	p11-kit/rpc-client.c \
	p11-kit/uri.c \
	p11-kit/virtual.c p11-kit/virtual.h \
	p11-kit/virtual-fixed.h \
	$(inc_HEADERS)

BUILT_SOURCES += \
	p11-kit/virtual-fixed-generated.h \
	$(NULL)

p11-kit/virtual.c: p11-kit/virtual-fixed-generated.h

CLEANFILES += \
	p11-kit/virtual-fixed-generated.h \
	$(NULL)

p11-kit/virtual-fixed-generated.h: Makefile
	$(AM_V_GEN)rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
	  echo; \
	  counter=0; \
	  while test $$counter -lt $(closures); do \
	    echo "P11_VIRTUAL_FIXED_FUNCTIONS($$counter)"; \
	    counter=`expr $$counter + 1`; \
	  done; \
	  echo; \
	  echo "CK_FUNCTION_LIST_3_0 p11_virtual_fixed[P11_VIRTUAL_MAX_FIXED] = {"; \
	  counter=0; \
	  while test $$counter -lt $(closures); do \
	    echo "	P11_VIRTUAL_FIXED_INITIALIZER($$counter),"; \
	    counter=`expr $$counter + 1`; \
	  done; \
	  echo '};'; \
	  echo; \
	  counter=0; \
	  while test $$counter -lt $(closures); do \
	    echo "P11_VIRTUAL_FIXED_GET_FUNCTION_LIST($$counter)"; \
	    counter=`expr $$counter + 1`; \
	  done; \
	} > $@-t && \
	mv -f $@-t $@

lib_LTLIBRARIES += \
	libp11-kit.la

COMMON_CFLAGS = \
	-DP11_SYSTEM_CONFIG_FILE=\""$(p11_system_config_file)"\" \
	-DP11_SYSTEM_CONFIG_MODULES=\""$(p11_system_config_modules)"\" \
	-DP11_PACKAGE_CONFIG_MODULES=\""$(p11_package_config_modules)"\" \
	-DP11_USER_CONFIG_FILE=\""$(p11_user_config_file)"\" \
	-DP11_USER_CONFIG_MODULES=\""$(p11_user_config_modules)"\" \
	-DP11_MODULE_PATH=\""$(p11_module_path)"\" \
	$(LIBFFI_CFLAGS) \
	$(NULL)

COMMON_LIBS = \
	libp11-common.la \
	libp11-library.la \
	$(LIBFFI_LIBS) \
	$(LTLIBINTL) \
	$(NULL)

libp11_kit_la_CFLAGS = $(COMMON_CFLAGS)

libp11_kit_la_LDFLAGS = \
	$(LDFLAGS_Z_NODELETE) \
	-no-undefined \
	-version-info $(P11KIT_LT_RELEASE)

if HAVE_LD_VERSION_SCRIPT
libp11_kit_la_LDFLAGS += -Wl,--version-script=$(srcdir)/p11-kit/libp11-kit.map
else
libp11_kit_la_LDFLAGS += -export-symbols-regex '^C_GetFunctionList|^C_GetInterface|^p11_kit_'
endif

libp11_kit_la_SOURCES = \
	p11-kit/proxy.c p11-kit/proxy.h p11-kit/proxy-init.c \
	p11-kit/rpc-server.c \
	$(NULL)

libp11_kit_la_LIBADD = \
	libp11-kit-internal.la \
	$(COMMON_LIBS) \
	$(NULL)

noinst_LTLIBRARIES += \
	libp11-kit-internal.la \
	$(NULL)

check_LTLIBRARIES += \
	libp11-kit-testable.la \
	libp11-kit-pkcs11-gnu.la \
	$(NULL)

libp11_kit_internal_la_LDFLAGS = -no-undefined
libp11_kit_internal_la_CFLAGS = $(COMMON_CFLAGS)
libp11_kit_internal_la_SOURCES = $(COMMON_SRCS)

libp11_kit_testable_la_LDFLAGS = -no-undefined
libp11_kit_testable_la_SOURCES = \
	$(libp11_kit_internal_la_SOURCES) \
	$(libp11_kit_la_SOURCES) \
	$(NULL)
libp11_kit_testable_la_LIBADD = $(COMMON_LIBS)

pkcs11_gnu_sources = \
	p11-kit/uri.gnu.c \
	p11-kit/iter.gnu.c \
	p11-kit/pin.gnu.c \
	$(NULL)

BUILT_SOURCES += $(pkcs11_gnu_sources)
CLEANFILES += $(pkcs11_gnu_sources)

p11-kit/uri.gnu.c: p11-kit/uri.h
p11-kit/iter.gnu.c: p11-kit/iter.h
p11-kit/pin.gnu.c: p11-kit/pin.h

SUFFIXES += .h .gnu.c
.h.gnu.c:
	$(AM_V_GEN) src=$<; dst=$@; rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
	  echo; \
	  echo '#include <stdlib.h>'; \
	  echo '#include "p11-kit/p11-kit.h"'; \
	  cat $$src; \
	  echo "void *$${dst}_funcs[] = {" | sed 's/[^][ *a-z0-9_={]/_/g'; \
	  sed -n -e '/^typedef/d' -e 's/.* \(p11_kit_[^ ]*\) *(.*/	\1,/p' $<; \
	  echo '};'; \
	} > $@-t && \
	mv -f $@-t $@

libp11_kit_pkcs11_gnu_la_LDFLAGS = -no-undefined
libp11_kit_pkcs11_gnu_la_SOURCES = $(pkcs11_gnu_sources)
libp11_kit_pkcs11_gnu_la_CFLAGS = -DCRYPTOKI_GNU=1 -DP11_KIT_FUTURE_UNSTABLE_API=1

if OS_WIN32

libp11_kit_testable_la_CFLAGS = \
	-DP11_SYSTEM_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/fixtures/system-pkcs11.conf"\" \
	-DP11_SYSTEM_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/system-modules/win32"\" \
	-DP11_PACKAGE_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/package-modules/win32"\" \
	-DP11_USER_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/fixtures/user-pkcs11.conf"\" \
	-DP11_USER_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/user-modules/win32"\" \
	-DP11_MODULE_PATH=\""$(abs_top_builddir)/.libs"\" \
	$(LIBFFI_CFLAGS) \
	$(NULL)

else

libp11_kit_testable_la_CFLAGS = \
	-DP11_SYSTEM_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/fixtures/system-pkcs11.conf"\" \
	-DP11_SYSTEM_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/system-modules"\" \
	-DP11_PACKAGE_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/package-modules"\" \
	-DP11_USER_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/fixtures/user-pkcs11.conf"\" \
	-DP11_USER_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/user-modules"\" \
	-DP11_MODULE_PATH=\""$(abs_top_builddir)/.libs"\" \
	$(LIBFFI_CFLAGS) \
	$(NULL)

# Proxy module is actually same as library, so install a link
install-exec-hook:
	for i in so dylib; do \
		test -f $(DESTDIR)$(libdir)/libp11-kit.$$i && \
			$(LN_S) -f `readlink $(DESTDIR)$(libdir)/libp11-kit.$$i` $(DESTDIR)$(libdir)/p11-kit-proxy.$$i || true; \
	done
	$(MKDIR_P) $(DESTDIR)$(p11_package_config_modules)

uninstall-local:
	for i in so dylib; do \
		rm -f $(DESTDIR)$(libdir)/p11-kit-proxy.$$i; \
	done

endif

if !OS_WIN32
module_LTLIBRARIES += \
	p11-kit-client.la

p11_kit_client_la_LDFLAGS = \
	-no-undefined -module -avoid-version \
	-version-info $(P11KIT_LT_RELEASE) \
	-export-symbols-regex '^C_GetFunctionList|^C_GetInterface' \
	$(NULL)

p11_kit_client_la_CFLAGS = $(COMMON_CFLAGS)

p11_kit_client_la_SOURCES = \
	p11-kit/client.c p11-kit/client.h p11-kit/client-init.c \
	$(NULL)

p11_kit_client_la_LIBADD = $(libp11_kit_la_LIBADD)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = p11-kit/p11-kit-1.pc

exampledir = $(p11_system_config)
example_DATA = p11-kit/pkcs11.conf.example

EXTRA_DIST += \
	p11-kit/docs.h \
	p11-kit/gen-pkcs11-gnu.sh \
	p11-kit/gen-virtual-fixed.sh \
	p11-kit/meson.build \
	p11-kit/meson_post_install.sh \
	p11-kit/libp11-kit.map \
	p11-kit/libp11-kit-0.dll.def \
	p11-kit/p11-module.map \
	p11-kit/p11-module.def \
	p11-kit/p11v3-module.map \
	p11-kit/p11v3-module.def \
	p11-kit/pkcs11-gnu.c \
	$(NULL)

bin_PROGRAMS += p11-kit/p11-kit

p11_kit_p11_kit_CFLAGS = $(COMMON_CFLAGS)

p11_kit_p11_kit_SOURCES = \
	p11-kit/lists.c \
	p11-kit/p11-kit.c \
	p11-kit/print-config.c \
	$(NULL)

p11_kit_p11_kit_LDADD = \
	libp11-kit.la \
	libp11-kit-internal.la \
	libp11-tool.la \
	libp11-common.la \
	$(LTLIBINTL) \
	$(NULL)

if WITH_BASH_COMPLETION
bashcomp_DATA += bash-completion/p11-kit
endif

private_PROGRAMS += p11-kit/p11-kit-remote

p11_kit_p11_kit_remote_SOURCES = \
	p11-kit/remote.c \
	$(NULL)

p11_kit_p11_kit_remote_LDADD = \
	libp11-tool.la \
	libp11-common.la \
	libp11-kit.la \
	$(NULL)

check_PROGRAMS += p11-kit/p11-kit-remote-testable
p11_kit_p11_kit_remote_testable_SOURCES = $(p11_kit_p11_kit_remote_SOURCES)

p11_kit_p11_kit_remote_testable_LDADD = \
	libp11-tool.la \
	libp11-common.la \
	libp11-kit-testable.la \
	$(NULL)

private_PROGRAMS += p11-kit/p11-kit-server

p11_kit_p11_kit_server_SOURCES = \
	p11-kit/server.c \
	$(NULL)

p11_kit_p11_kit_server_LDADD = \
	libp11-tool.la \
	libp11-common.la \
	libp11-kit.la \
	$(LIBSYSTEMD_LIBS) \
	$(NULL)

p11_kit_p11_kit_server_CFLAGS = \
	-DP11_KIT_REMOTE=\"p11-kit-remote\" \
	$(COMMON_CFLAGS) \
	$(LIBSYSTEMD_CFLAGS) \
	$(NULL)

check_PROGRAMS += p11-kit/p11-kit-server-testable
p11_kit_p11_kit_server_testable_SOURCES = $(p11_kit_p11_kit_server_SOURCES)

p11_kit_p11_kit_server_testable_LDADD = \
	libp11-tool.la \
	libp11-common.la \
	libp11-kit-testable.la \
	$(LIBSYSTEMD_LIBS) \
	$(NULL)

p11_kit_p11_kit_server_testable_CFLAGS = \
	-DP11_KIT_REMOTE=\"p11-kit-remote-testable\" \
	$(COMMON_CFLAGS) \
	$(LIBSYSTEMD_CFLAGS) \
	$(NULL)

if WITH_SYSTEMD
p11-kit/p11-kit-server.service: p11-kit/p11-kit-server.service.in
	$(AM_V_GEN)rm -f $@-t $@ && \
	sed 's|@bindir[@]|$(bindir)|g' $< > $@-t && \
	mv -f $@-t $@

CLEANFILES += p11-kit/p11-kit-server.service

systemduserunit_DATA = \
	p11-kit/p11-kit-server.socket \
	p11-kit/p11-kit-server.service \
	$(NULL)
endif

EXTRA_DIST += p11-kit/p11-kit-server.socket p11-kit/p11-kit-server.service.in

# Tests ----------------------------------------------------------------

p11_kit_LIBS = \
	libp11-kit-testable.la \
	libp11-test.la \
	libp11-common.la \
	$(LTLIBINTL)

c_tests += \
	test-progname \
	test-util \
	test-conf \
	test-uri \
	test-pin \
	test-init \
	test-modules \
	test-deprecated \
	test-proxy \
	test-iter \
	test-rpc \
	$(NULL)

if !OS_WIN32
c_tests += test-server
sh_tests += p11-kit/test-server.sh
endif

test_conf_SOURCES = p11-kit/test-conf.c
test_conf_LDADD = $(p11_kit_LIBS)

test_deprecated_SOURCES = p11-kit/test-deprecated.c
test_deprecated_LDADD = $(p11_kit_LIBS)
test_deprecated_CFLAGS = $(AM_CPPFLAGS) $(libp11_kit_testable_la_CFLAGS)

test_init_SOURCES = p11-kit/test-init.c
test_init_LDADD = $(p11_kit_LIBS)
test_init_CFLAGS = $(AM_CPPFLAGS) $(libp11_kit_testable_la_CFLAGS)

test_iter_SOURCES = p11-kit/test-iter.c
test_iter_LDADD = $(p11_kit_LIBS)

test_modules_SOURCES = p11-kit/test-modules.c
test_modules_LDADD = $(p11_kit_LIBS)

test_pin_SOURCES = p11-kit/test-pin.c
test_pin_LDADD = $(p11_kit_LIBS)

test_progname_SOURCES = p11-kit/test-progname.c
test_progname_LDADD = $(p11_kit_LIBS)

test_proxy_SOURCES = p11-kit/test-proxy.c
test_proxy_LDADD = $(p11_kit_LIBS)

test_rpc_SOURCES = p11-kit/test-rpc.c
test_rpc_LDADD = $(p11_kit_LIBS)

test_server_SOURCES = p11-kit/test-server.c
test_server_LDADD = $(p11_kit_LIBS)
test_server_CFLAGS = $(AM_CPPFLAGS) $(libp11_kit_testable_la_CFLAGS)

test_uri_SOURCES = p11-kit/test-uri.c
test_uri_LDADD = $(p11_kit_LIBS)

test_util_SOURCES = p11-kit/test-util.c
test_util_LDADD = $(p11_kit_LIBS)

check_PROGRAMS += \
	p11-kit/print-messages \
	p11-kit/frob-setuid

p11_kit_print_messages_SOURCES = p11-kit/print-messages.c
p11_kit_print_messages_LDADD = $(p11_kit_LIBS)

sh_tests += p11-kit/test-messages.sh

p11_kit_frob_setuid_SOURCES = p11-kit/frob-setuid.c
p11_kit_frob_setuid_LDADD = $(p11_kit_LIBS)

c_tests += \
	test-virtual \
	test-managed \
	test-log \
	test-filter \
	test-transport \
	$(NULL)

test_log_SOURCES = p11-kit/test-log.c
test_log_LDADD = $(p11_kit_LIBS)

test_filter_SOURCES = p11-kit/test-filter.c
test_filter_LDADD = $(p11_kit_LIBS)

test_managed_SOURCES = p11-kit/test-managed.c
test_managed_LDADD = $(p11_kit_LIBS)

test_transport_SOURCES = p11-kit/test-transport.c
test_transport_LDADD = $(p11_kit_LIBS)
test_transport_CFLAGS = $(AM_CPPFLAGS) $(libp11_kit_testable_la_CFLAGS)

test_virtual_SOURCES = p11-kit/test-virtual.c
test_virtual_LDADD = $(p11_kit_LIBS)

check_LTLIBRARIES += \
	mock-one.la \
	mock-two.la \
	mock-three.la \
	mock-four.la \
	mock-five.la \
	mock-seven.la \
	mock-eight.la \
	mock-nine.la \
	mock-ten.la

mock_one_la_SOURCES = p11-kit/mock-module-ep.c
mock_one_la_LIBADD = libp11-test.la libp11-common.la
mock_one_la_LDFLAGS = \
	-module -avoid-version -rpath /nowhere \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

mock_two_la_SOURCES = p11-kit/mock-module-ep2.c
mock_two_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_two_la_LIBADD = $(mock_one_la_LIBADD)

mock_three_la_SOURCES = $(mock_one_la_SOURCES)
mock_three_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_three_la_LIBADD = $(mock_one_la_LIBADD)

mock_four_la_SOURCES = $(mock_one_la_SOURCES)
mock_four_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_four_la_LIBADD = $(mock_one_la_LIBADD)

mock_five_la_SOURCES = p11-kit/mock-module-ep3.c
mock_five_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_five_la_LIBADD = $(mock_one_la_LIBADD)

if !OS_WIN32
check_LTLIBRARIES += mock-six.la
mock_six_la_SOURCES = p11-kit/mock-module-ep4.c
mock_six_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_six_la_LIBADD = $(mock_one_la_LIBADD)
endif

mock_seven_la_SOURCES = p11-kit/mock-module-ep5.c
mock_seven_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_seven_la_LIBADD = $(mock_one_la_LIBADD)

mock_eight_la_SOURCES = p11-kit/mock-module-ep6.c
mock_eight_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_eight_la_LIBADD = $(mock_one_la_LIBADD)

mock_nine_la_SOURCES = p11-kit/mock-module-ep7.c
mock_nine_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_nine_la_LIBADD = $(mock_one_la_LIBADD)

mock_ten_la_SOURCES = p11-kit/mock-module-ep8.c
mock_ten_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_ten_la_LIBADD = $(mock_one_la_LIBADD)

EXTRA_DIST += \
	p11-kit/fixtures \
	p11-kit/test-mock.c \
	p11-kit/test-messages.sh \
	p11-kit/test-server.sh \
	$(NULL)
