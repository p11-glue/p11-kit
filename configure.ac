AC_PREREQ(2.61)

AC_INIT([p11-kit],
	[0.24.1],
	[https://github.com/p11-glue/p11-kit/issues],
	[p11-kit],
	[https://p11-glue.github.io/p11-glue/p11-kit.html])

# ------------------------------------------------------------------------------
# p11-kit libtool versioning
# CURRENT : REVISION : AGE
#   +1    :     0    : +1   == new interface that does not break old one.
#   +1    :     0    :  0   == removed an interface. Breaks old apps.
#    ?    :    +1    :  ?   == internal changes that doesn't break anything.

P11KIT_CURRENT=3
P11KIT_REVISION=0
P11KIT_AGE=3

# ------------------------------------------------------------------------------
# p11-kit RPC protocol versions
P11KIT_RPC_MIN=0
P11KIT_RPC_MAX=0

# ------------------------------------------------------------------------------

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([build/m4])
AC_CONFIG_AUX_DIR([build/litter])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
AM_INIT_AUTOMAKE([1.12 dist-xz no-dist-gzip foreign subdir-objects])
AM_SANITY_CHECK
AM_MAINTAINER_MODE([enable])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)
m4_ifdef([PKG_PREREQ], [PKG_PREREQ(0.29)],
  [m4_fatal([pkg.m4 is too old; copy the latest version in build/m4])])

dnl Enable platform specific extensions.
AC_USE_SYSTEM_EXTENSIONS

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

dnl Check if -Wl,--version-script is supported by the linker
gl_LD_VERSION_SCRIPT

dnl libp11-kit installs pthread_atfork to count forks in ELF
dnl constructor, which could cause crash if the library is unloaded.
dnl Use the linker flag "-z nodelete" to prevent unloading, if
dnl available.
SAVE_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,-z -Wl,nodelete"
AC_MSG_CHECKING([whether linker understands -z nodelete])
AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
	       [LDFLAGS_Z_NODELETE="-Wl,-z -Wl,nodelete"; has_option=yes],
	       [LDFLAGS_Z_NODELETE=""; has_option=no])
AC_MSG_RESULT($has_option)
LDFLAGS="$SAVE_LDFLAGS"
AC_SUBST(LDFLAGS_Z_NODELETE)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG

LINGUAS=""
AM_GNU_GETTEXT([external], [need-ngettext])
AM_GNU_GETTEXT_VERSION([0.19.8])
m4_ifdef([AM_GNU_GETTEXT_REQUIRE_VERSION],[
AM_GNU_GETTEXT_REQUIRE_VERSION([0.19.8])
])

if test "$enable_static" = "yes"; then
	AC_MSG_ERROR([p11-kit cannot be used as a static library])
fi

AC_MSG_CHECKING([for win32])
case "$host" in
	*-*-mingw*)
		AC_DEFINE_UNQUOTED(OS_WIN32, 1, [Building for win32])
		os_win32=yes
		os_unix=no
		;;
	*)
		AC_DEFINE_UNQUOTED(OS_UNIX, 1, [Building for unix])
		os_win32=no
		os_unix=yes
		;;
esac
AC_MSG_RESULT([$os_win32])
AM_CONDITIONAL(OS_WIN32, test "$os_win32" = "yes")

AC_C_BIGENDIAN

# ------------------------------------------------------------------------------
# Checks for libraries and headers

AC_HEADER_STDBOOL

AC_CHECK_SIZEOF([unsigned long])

if test "$os_unix" = "yes"; then
	AC_CHECK_FUNC([pthread_create], , [
		AC_CHECK_LIB(pthread, pthread_create, , [
			AC_MSG_ERROR([could not find pthread_create])
		])
	])

	AC_CHECK_FUNC([nanosleep], , [
		AC_SEARCH_LIBS([nanosleep], [rt], , [
			AC_MSG_ERROR([could not find nanosleep])
		])
	])

	AC_SEARCH_LIBS([dlopen], [dl dld], [], [
		AC_MSG_ERROR([could not find dlopen])
	])

	# for Solaris we need -lsocket -lnsl for socket stuff, gethostbyname
	# is just a dummy to find -lnsl
	AC_SEARCH_LIBS([gethostbyname], [nsl])
	AC_SEARCH_LIBS([connect], [socket], [], [
		AC_MSG_ERROR([could not find socket])
	])

	AC_CHECK_HEADERS([locale.h], [
		AC_CHECK_TYPES([locale_t], [], [], [[#include <locale.h>]])
		AC_CHECK_FUNCS([newlocale strerror_l])
	])

	# These are things we can work around
	AC_CHECK_HEADERS([sys/resource.h sys/un.h ucred.h])
	AC_CHECK_MEMBERS([struct dirent.d_type],,,[#include <dirent.h>])
	AC_CHECK_FUNCS([getprogname getexecname basename mkstemp mkdtemp])
	AC_CHECK_FUNCS([getauxval getresuid secure_getenv])
	AC_CHECK_FUNCS([strnstr memdup strndup strerror_r])
	AC_CHECK_FUNCS([reallocarray])
	AC_CHECK_DECLS([reallocarray], [], [], [[#include <stdlib.h>]])
	AC_CHECK_FUNCS([fdwalk])
	AC_CHECK_FUNCS([setenv])
	AC_CHECK_FUNCS([getpeereid])
	AC_CHECK_FUNCS([getpeerucred])
	AC_CHECK_FUNCS([issetugid])

	AC_CACHE_CHECK([for thread-local storage class],
		[ac_cv_tls_keyword],
		[ac_cv_tls_keyword=
		for keyword in _Thread_local __thread; do
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdlib.h>]],
			[[static ]$keyword[ foo;]])],
			[ac_cv_tls_keyword=$keyword])
		done])
	if test -n "$ac_cv_tls_keyword"; then
		AC_DEFINE_UNQUOTED([P11_TLS_KEYWORD], [$ac_cv_tls_keyword], [the compiler keyword to define thread-local storage])
	fi

	# Required functions
	AC_CHECK_FUNCS([gmtime_r],
		[AC_DEFINE([HAVE_GMTIME_R], 1, [Whether gmtime_r() is available])],
		[AC_MSG_ERROR([could not find required gmtime_r() function])])

	# Check if these are declared and/or available to link against
	AC_CHECK_DECLS([program_invocation_short_name], [], [], [#include <errno.h>])
	AC_MSG_CHECKING([whether program_invocation_short_name is available])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <errno.h>]],
	                                [[program_invocation_short_name = "test";]])],
	               [AC_DEFINE([HAVE_PROGRAM_INVOCATION_SHORT_NAME], [1],
	                          [Whether program_invocation_short_name available])
	                AC_MSG_RESULT([yes])],
	               [AC_MSG_RESULT([no])])
	AC_CHECK_DECLS([__progname])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[extern char *__progname;]], [[__progname=(char*)0;]])],
		[AC_DEFINE(HAVE___PROGNAME, [1], [Whether __progname available])])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[extern int __libc_enable_secure;]], [[__libc_enable_secure = 0;]])],
		[AC_DEFINE(HAVE___LIBC_ENABLE_SECURE, [1], [Whether __libc_enable_secure available])])
	AC_CHECK_TYPES([sighandler_t, sig_t, __sighandler_t], [], [],
		[[#include <sys/types.h>
		  #include <signal.h>]])

	AC_MSG_CHECKING([whether vsock support is available])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sys/socket.h>
					  #include <linux/vm_sockets.h>]],
	                                [[struct sockaddr_vm sa = {
					  .svm_family = AF_VSOCK,
					  .svm_cid = VMADDR_CID_ANY,
					  };
					  (void)&sa;
					  return 0;]])],
	               [AC_DEFINE([HAVE_VSOCK], [1],
	                          [Whether vsock support available])
	                AC_MSG_RESULT([yes])],
	               [AC_MSG_RESULT([no])])

fi

# These are thngs we can work around
AC_CHECK_FUNCS([asprintf vasprintf vsnprintf])
AC_CHECK_DECLS([asprintf, vasprintf], [], [], [[#include <stdio.h>]])

AC_CHECK_LIB(intl, dgettext)

# ------------------------------------------------------------------------------
# PKCS#11 Directories

AC_ARG_WITH([module-config],
            [AS_HELP_STRING([--with-module-config], [Module configuration files shipped by packages])],
            [module_config=$withval],
            [module_config='${pkgdatadir}/modules'])

AC_ARG_WITH([system-config],
            [AS_HELP_STRING([--with-system-config], [Change PKCS#11 system config directory])],
            [system_config_dir=$withval],
            [system_config_dir=$sysconfdir/pkcs11])

AC_ARG_WITH([user-config],
            [AS_HELP_STRING([--with-user-config], [Change PKCS#11 user config directory])],
            [user_config_dir=$withval],
            [user_config_dir="~/.config/pkcs11"])

AC_ARG_WITH([module-path],
            [AS_HELP_STRING([--with-module-path], [Load modules with relative path names from here])],
            [module_path=$withval],
            [module_path=$libdir/pkcs11])

# We expand these so we have concrete paths
p11_system_config=$system_config_dir
p11_system_config_file=$p11_system_config/pkcs11.conf
p11_system_config_modules=$p11_system_config/modules
p11_package_config_modules=$module_config
p11_user_config=$user_config_dir
p11_user_config_file="$p11_user_config/pkcs11.conf"
p11_user_config_modules="$p11_user_config/modules"
p11_module_path="$module_path"

AC_SUBST(p11_system_config)
AC_SUBST(p11_system_config_file)
AC_SUBST(p11_system_config_modules)
AC_SUBST(p11_package_config_modules)
AC_SUBST(p11_user_config)
AC_SUBST(p11_user_config_file)
AC_SUBST(p11_user_config_modules)
AC_SUBST(p11_module_path)

# --------------------------------------------------------------------
# libtasn1 support

AC_ARG_WITH([libtasn1],
            AS_HELP_STRING([--without-libtasn1],
                           [Disable dependency on libtasn1])
)

AS_IF([test "$with_libtasn1" != "no"], [
	PKG_CHECK_MODULES([LIBTASN1], [libtasn1 >= 2.3], [],
		[AC_MSG_ERROR([libtasn1 not found. Building without it results in significant loss of functionality. To proceed use --without-libtasn1])]
	)
	AC_SUBST(LIBTASN1_CFLAGS)
	AC_SUBST(LIBTASN1_LIBS)
	AC_PATH_PROG([ASN1PARSER], [asn1Parser])
	with_libtasn1="yes"
	AC_DEFINE_UNQUOTED(WITH_ASN1, 1, [Build with libtasn1 and certificate support])
])

AM_CONDITIONAL(WITH_ASN1, test "$with_libtasn1" = "yes")

# --------------------------------------------------------------------
# libffi

AC_ARG_WITH([libffi],
            AS_HELP_STRING([--without-libffi],
                           [Don't use libffi for building closures]))

if test "$with_libffi" != "no"; then
	PKG_CHECK_MODULES(LIBFFI, [libffi >= 3.0.0])
	AC_DEFINE_UNQUOTED(WITH_FFI, 1, [Use libffi for building closures])
	AC_SUBST(LIBFFI_CFLAGS)
	AC_SUBST(LIBFFI_LIBS)

	with_libffi="yes"
fi

AM_CONDITIONAL(WITH_FFI, test "$with_libffi" = "yes")

AC_ARG_WITH([closures],
	    [AS_HELP_STRING([--with-closures[=NUM]],
		            [the number of precompiled closures, used when libffi is unavailable])],
	    [closures=$withval],
	    [closures=64])

if test "$closures" -lt 1; then
	AC_MSG_ERROR([at least one closure must be compiled in])
fi

AC_DEFINE_UNQUOTED(P11_VIRTUAL_MAX_FIXED, [$closures], [the number of closures])
AC_SUBST(closures)

# --------------------------------------------------------------------
# Hash implementation

AC_ARG_WITH([hash-impl],
            AS_HELP_STRING([--with-hash-impl=@<:@freebl/internal@:>@],
                           [Choose the hash implementation to use])
)

AS_IF([test "$with_hash_impl" = ""], [with_hash_impl=internal])

AS_CASE([$with_hash_impl],
	[freebl], [
		AC_CHECK_LIB(freebl3, NSSLOW_Init,
			[
				HASH_LIBS=-lfreebl3
				AC_DEFINE_UNQUOTED(WITH_FREEBL, 1, [Use freebl for hash implementation])
			],
			AC_MSG_ERROR([could not find the freebl3 library])
		)
	],

	[internal], [
		HASH_LIBS=
	],

	[
		AC_MSG_ERROR([unsupported hash impl: $with_hash_impl])
	]
)

AC_SUBST(HASH_LIBS)

# --------------------------------------------------------------------
# Trust Module

AC_ARG_ENABLE([trust-module],
              AS_HELP_STRING([--disable-trust-module],
                             [Disable building the trust module])
)

AC_MSG_CHECKING([if trust module is enabled])
AS_IF([test "$with_libtasn1" != "yes"], [
	AS_IF([test "$enable_trust_module" = "yes"], [
		AC_MSG_ERROR([--with-libtasn1 is needed in order to build the trust module])
	])
	AS_IF([test "$enable_trust_module" != "no"], [
		AC_MSG_WARN([--with-libtasn1 is needed in order to build the trust module, disabling])
	])
	enable_trust_module="no"
])

AS_IF([test "$enable_trust_module" != "no"], [enable_trust_module="yes"])
AM_CONDITIONAL(WITH_TRUST_MODULE, test "$enable_trust_module" = "yes")
AC_MSG_RESULT([$enable_trust_module])

AC_ARG_WITH([trust-paths],
            AS_HELP_STRING([--with-trust-paths=@<:@path@:>@]:
                           [input paths for trust module])
)

AC_MSG_CHECKING([for trust module paths])

# This option was disabled, no anchors
if test "$with_trust_paths" = "no"; then
	with_trust_paths=""
	AC_MSG_RESULT([disabled])

elif test "$enable_trust_module" != "yes"; then
	if test "$with_trust_paths" != ""; then
		AC_MSG_ERROR([need --enable-trust-module in order to specify trust module paths.])
	fi
	with_trust_paths=""
	AC_MSG_RESULT([disabled])

# Option was not set, try to detect
elif test "$with_trust_paths" = "" || test "$with_trust_paths" = "yes"; then
	with_trust_paths=""
	for f in /etc/pki/tls/certs/ca-bundle.crt \
		/etc/ssl/certs/ca-certificates.crt \
		/etc/ssl/ca-bundle.pem \
		/etc/ssl/ca-bundle.crt; do
		if test -f "$f"; then
			with_trust_paths="$f"
			break
		fi
	done

	if test "$with_trust_paths" = ""; then
		AC_MSG_ERROR([could not find. Use --with-trust-paths=/path to set, or --without-trust-paths to disable])
	fi

	AC_MSG_RESULT($with_trust_paths)

else
	# Anchors explicitly set
	AC_MSG_RESULT($with_trust_paths)
fi

AC_DEFINE_UNQUOTED(TRUST_PATHS, ["$with_trust_paths"], [The trust module input paths])
AC_SUBST(with_trust_paths)

# --------------------------------------------------------------------
# RPC

AC_ARG_WITH([rpc-min],
            [AS_HELP_STRING([--with-rpc-min], [Minimum RPC protocol version we support])],
            [rpc_min=$withval],
            [rpc_min=$P11KIT_RPC_MIN])

AC_ARG_WITH([rpc-max],
            [AS_HELP_STRING([--with-rpc-max], [Maximum RPC protocol version we support])],
            [rpc_max=$withval],
            [rpc_max=$P11KIT_RPC_MAX])

AS_IF([test $rpc_min -lt $P11KIT_RPC_MIN || test $rpc_min -gt $P11KIT_RPC_MAX], [
	AC_MSG_ERROR([Out of range version specified with --with-rpc-min])
])

AS_IF([test $rpc_max -lt $P11KIT_RPC_MIN || test $rpc_max -gt $P11KIT_RPC_MAX], [
	AC_MSG_ERROR([Out of range version specified with --with-rpc-max])
])

AS_IF([test $rpc_min -gt $rpc_max], [
	AC_MSG_ERROR([Conflicting versions specified with --with-rpc-min and --with-rpc-max])
])

AC_DEFINE_UNQUOTED(P11_RPC_PROTOCOL_VERSION_MINIMUM, $rpc_min, [Minimum RPC protocol version we support])

AC_DEFINE_UNQUOTED(P11_RPC_PROTOCOL_VERSION_MAXIMUM, $rpc_max, [Maximum RPC protocol version we support])

# --------------------------------------------------------------------
# GTK Doc

dnl check for tools
AC_PATH_PROG([GTKDOC_CHECK],[gtkdoc-check])
AC_PATH_PROGS([GTKDOC_REBASE],[gtkdoc-rebase],[true])
AC_PATH_PROG([GTKDOC_MKPDF],[gtkdoc-mkpdf])
AC_PATH_PROG([GTKDOC_SCAN],[gtkdoc-scan])
AC_PATH_PROG([XSLTPROC], [xsltproc])

dnl for overriding the documentation installation directory
AC_ARG_WITH([html-dir],
	AS_HELP_STRING([--with-html-dir=PATH], [path to installed docs]),,
	               [with_html_dir='${datadir}/gtk-doc/html'])
HTML_DIR="$with_html_dir"
AC_SUBST([HTML_DIR])

dnl enable/disable documentation building
AC_ARG_ENABLE([doc],
	AS_HELP_STRING([--enable-doc],
	               [build documentation using gtk-doc [[default=no]]]),,
              [enable_doc=no])

if test x$enable_doc = xyes; then
	if test -z "$GTKDOC_SCAN"; then
		AC_MSG_ERROR([gtk-doc not installed and --enable-doc requested])
	fi
	if test -z "$XSLTPROC"; then
		AC_MSG_ERROR([the xsltproc command was not found and --enable-doc requested])
	fi
	doc_status="yes (manual, reference)"
else
	enable_doc=no
	doc_status="no (no manual or reference)"
fi

AC_MSG_CHECKING([whether to build documentation])
AC_MSG_RESULT($enable_doc)

dnl enable/disable output formats
AC_ARG_ENABLE([doc-html],
	AS_HELP_STRING([--enable-doc-html],
	               [build documentation in html format [[default=yes]]]),,
	          [enable_doc_html=yes])
AC_ARG_ENABLE([doc-pdf],
	AS_HELP_STRING([--enable-doc-pdf],
	               [build documentation in pdf format [[default=no]]]),,
              [enable_doc_pdf=no])

if test -z "$GTKDOC_MKPDF"; then
	enable_doc_pdf=no
fi

AM_CONDITIONAL(ENABLE_GTK_DOC, [test x$enable_doc = xyes])
AM_CONDITIONAL(GTK_DOC_BUILD_HTML, [test x$enable_doc_html = xyes])
AM_CONDITIONAL(GTK_DOC_BUILD_PDF, [test x$enable_doc_pdf = xyes])
AM_CONDITIONAL(GTK_DOC_USE_LIBTOOL, [test -n "$LIBTOOL"])
AM_CONDITIONAL(GTK_DOC_USE_REBASE, [test -n "$GTKDOC_REBASE"])

# --------------------------------------------------------------------
# Compilation and linking options

AC_MSG_CHECKING([for debug mode])
AC_ARG_ENABLE(debug,
              AC_HELP_STRING([--enable-debug=no/default/yes],
              [Turn on or off debugging]))

if test "$enable_debug" != "no"; then
	AC_DEFINE_UNQUOTED(WITH_DEBUG, 1, [Print debug output])
	AC_DEFINE_UNQUOTED(_DEBUG, 1, [In debug mode])
	CFLAGS="$CFLAGS -g"
fi

if test "$enable_debug" = "yes"; then
	debug_status="yes (-g, -O0, debug output)"
	CFLAGS="$CFLAGS -O0"
elif test "$enable_debug" = "no"; then
	debug_status="no (no debug output, NDEBUG)"
	AC_DEFINE_UNQUOTED(NDEBUG, 1, [Disable glib assertions])
else
	debug_status="default (-g, debug output)"
fi

AC_MSG_RESULT($debug_status)

AC_MSG_CHECKING(for more warnings)
if test "$GCC" = "yes"; then
	CFLAGS="$CFLAGS \
		-Wall -Wstrict-prototypes -Wmissing-declarations \
		-Wmissing-prototypes -Wnested-externs -Wpointer-arith \
		-Wdeclaration-after-statement -Wformat=2 -Winit-self \
		-Waggregate-return -Wno-missing-format-attribute \
		-fno-strict-aliasing -fno-common"

	for option in -Wmissing-include-dirs -Wundef; do
		SAVE_CFLAGS="$CFLAGS"
		CFLAGS="$CFLAGS $option"
		AC_MSG_CHECKING([whether gcc understands $option])
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])],
				  [has_option=yes],
				  [has_option=no])
		AC_MSG_RESULT($has_option)
		if test $has_option = no; then
			CFLAGS="$SAVE_CFLAGS"
		fi
	done
else
	AC_MSG_RESULT(no)
fi

AC_ARG_ENABLE(strict,
              [AS_HELP_STRING([--enable-strict], [Strict code compilation])]
             )

AC_MSG_CHECKING([build strict])

if test "$enable_strict" = "yes"; then
	CFLAGS="$CFLAGS -Werror"
	AC_DEFINE_UNQUOTED(WITH_STRICT, 1, [More strict checks])
	strict_status="yes (-Werror, fatals)"
else
	strict_status="no"
fi

AC_MSG_RESULT($strict_status)

AC_MSG_CHECKING([whether to build with gcov testing])
AC_ARG_ENABLE([coverage],
		[AS_HELP_STRING([--enable-coverage], [Whether to enable coverage testing ])],
		[],
		[enable_coverage=no])

AC_MSG_RESULT([$enable_coverage])

if test "$enable_coverage" = "yes"; then
	if test "$GCC" != "yes"; then
		AC_MSG_ERROR(Coverage testing requires GCC)
	fi

	AC_PATH_PROG(GCOV, gcov, no)
	if test "$GCOV" = "no" ; then
		AC_MSG_ERROR(gcov tool is not available)
	fi

	AC_PATH_PROG(LCOV, lcov, no)
	if test "$LCOV" = "no" ; then
		AC_MSG_ERROR(lcov tool is not installed)
	fi

	AC_PATH_PROG(GENHTML, genhtml, no)
	if test "$GENHTML" = "no" ; then
		AC_MSG_ERROR(lcov's genhtml tool is not installed)
	fi

	CFLAGS="$CFLAGS -O0 -g --coverage"
	LDFLAGS="$LDFLAGS --coverage"
fi

AM_CONDITIONAL([WITH_COVERAGE], [test "$enable_coverage" = "yes"])
AC_SUBST(LCOV)
AC_SUBST(GCOV)
AC_SUBST(GENHTML)

# ---------------------------------------------------------------------

P11KIT_LT_RELEASE=$P11KIT_CURRENT:$P11KIT_REVISION:$P11KIT_AGE
AC_SUBST(P11KIT_LT_RELEASE)

echo $PACKAGE_VERSION | tr '.' ' ' | while read major minor unused; do
	AC_DEFINE_UNQUOTED(PACKAGE_MAJOR, $major, [Major version of package])
	AC_DEFINE_UNQUOTED(PACKAGE_MINOR, $minor, [Minor version of package])
	break
done

case "$host" in
*-*-darwin*)
	# It seems like libtool lies about this see:
	# https://bugs.freedesktop.org/show_bug.cgi?id=57714
	SHLEXT='.so'
	;;
*)
	eval SHLEXT=$shrext_cmds
	;;
esac

AC_DEFINE_UNQUOTED(SHLEXT, ["$SHLEXT"], [File extension for shared libraries])
AC_SUBST(SHLEXT)

AC_DEFINE_UNQUOTED(EXEEXT, ["$EXEEXT"], [File extension for executables])

privatedir='${libexecdir}/p11-kit'
AC_SUBST(privatedir)

# --------------------------------------------------------------------
# systemd

AC_ARG_WITH([systemd],
            AS_HELP_STRING([--without-systemd],
                           [Disable systemd socket activation]))

AS_IF([test "$with_systemd" != "no"], [
	PKG_CHECK_MODULES([LIBSYSTEMD], [libsystemd], [],
		[with_systemd=no])

	PKG_CHECK_VAR([systemduserunitdir], [systemd], [systemduserunitdir], [],
		[with_systemd=no])

	AS_IF([test "$with_systemd" != "no"], [
		with_systemd=yes
		AC_DEFINE_UNQUOTED(WITH_SYSTEMD, 1, [Build with systemd socket activation])
	])
])

AM_CONDITIONAL(WITH_SYSTEMD, [test "$with_systemd" = "yes"])

# --------------------------------------------------------------------
# bash completion

AC_ARG_WITH([bash-completion],
            AS_HELP_STRING([--without-bash-completion],
                           [Don't install bash completion files]))

AS_IF([test "$with_bash_completion" != "no"], [
	PKG_CHECK_VAR([bashcompdir], [bash-completion], [completionsdir],
		[with_bash_completion=yes])
	AC_SUBST(bashcompdir)
])

AM_CONDITIONAL(WITH_BASH_COMPLETION, [test "$with_bash_completion" = "yes"])


AC_CONFIG_FILES([Makefile
	doc/Makefile
	doc/manual/Makefile
	po/Makefile.in
	p11-kit/p11-kit-1.pc
	p11-kit/pkcs11.conf.example
	trust/test-init.sh
])
AC_OUTPUT

# Format paths arguments which should wrap correctly in the output
indent='\n                                     '
trust_status=$(echo "$with_trust_paths" | sed -e "s/:/$indent/g")

AC_MSG_NOTICE([build options:

    Host:                            $host
    Debug build:                     $debug_status
    Strict build:                    $strict_status
    Build documentation:             $doc_status
    System global config:            $p11_system_config_file
    System module config directory:  $p11_system_config_modules
    Package module config directory: $p11_package_config_modules
    User global config:              $p11_user_config_file
    User module config directory:    $p11_user_config_modules
    Load relative module paths from: $p11_module_path

    With libtasn1 dependency:        $with_libtasn1
    With libffi:                     $with_libffi
    With hash implementation:        $with_hash_impl
    With systemd:                    $with_systemd

    Build trust module:              $enable_trust_module
    Trust module paths:              $trust_status

    RPC protocol versions:           $rpc_min upto $rpc_max

])
