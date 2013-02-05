AC_PREREQ(2.61)

AC_INIT([p11-kit],
	[0.14],
	[https://bugs.freedesktop.org/enter_bug.cgi?product=p11-glue],
	[p11-kit],
	[http://p11-glue.freedesktop.org/p11-kit.html])

AC_USE_SYSTEM_EXTENSIONS

# ------------------------------------------------------------------------------
# p11-kit libtool versioning
# CURRENT : REVISION : AGE
#   +1    :     0    : +1   == new interface that does not break old one.
#   +1    :     0    :  0   == removed an interface. Breaks old apps.
#    ?    :    +1    :  ?   == internal changes that doesn't break anything.

P11KIT_CURRENT=0
P11KIT_REVISION=0
P11KIT_AGE=0

# ------------------------------------------------------------------------------

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([build/m4])
AM_INIT_AUTOMAKE([1.10])
AM_SANITY_CHECK
AM_MAINTAINER_MODE([enable])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O

LINGUAS=""
AM_GNU_GETTEXT([external], [need-ngettext])

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

# ------------------------------------------------------------------------------
# Checks for libraries and headers

if test "$os_unix" = "yes"; then
	AC_CHECK_LIB(pthread, pthread_mutex_lock,,
		[AC_MSG_ERROR([could not find pthread_mutex_lock])])
	AC_SEARCH_LIBS([dlopen], [dl dld], [],
		[AC_MSG_ERROR([could not find dlopen])])
	AC_SEARCH_LIBS([nanosleep], [rt], [],
		[AC_MSG_ERROR([could not find nanosleep])])
	AC_CHECK_MEMBERS([struct dirent.d_type],,,[#include <dirent.h>])
	AC_CHECK_HEADERS([err.h errno.h stdbool.h])
	AC_CHECK_FUNCS([getprogname getexecname memdup])

	# Check if these are declared and/or available to link against
	AC_CHECK_DECLS([program_invocation_short_name])
	AC_MSG_CHECKING([whether program_invocation_short_name is available])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <argp.h>]],
	                                [[program_invocation_short_name = "test";]])],
	               [AC_DEFINE([HAVE_PROGRAM_INVOCATION_SHORT_NAME], [1],
	                          [Whether program_invocation_short_name available])
	                AC_MSG_RESULT([yes])],
	               [AC_MSG_RESULT([no])])
	AC_CHECK_DECLS([__progname])
	AC_LINK_IFELSE([AC_LANG_SOURCE([extern char *__progname; void main() { }])],
		[AC_DEFINE(HAVE___PROGNAME, [1], [Whether __progname available])])
fi

AC_CHECK_LIB(intl, dgettext)

# ------------------------------------------------------------------------------
# PKCS#11 Directories

AC_ARG_WITH([system-config],
            [AS_HELP_STRING([--with-system-config], [Change PKCS#11 system config directory])],
            [system_config_dir=$withval],
            [system_config_dir=$sysconfdir/pkcs11])

AC_ARG_WITH([module-path],
            [AS_HELP_STRING([--with-module-path], [Load modules with relative path names from here])],
            [module_path=$withval],
            [module_path=$libdir/pkcs11])

# We expand these so we have concrete paths
p11_system_config=$system_config_dir
p11_system_config_file=$p11_system_config/pkcs11.conf
p11_system_config_modules=$p11_system_config/modules
p11_package_config_modules='${pkgdatadir}/modules'
p11_user_config="~/.pkcs11"
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
	doc_status="yes (manual, gtk-doc reference)"
else
	enable_doc=no
	doc_status="no (no manual, reference)"
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
		-fno-strict-aliasing"

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

	CFLAGS="$CFLAGS -O0 -g -fprofile-arcs -ftest-coverage"
	LDFLAGS="$LDFLAGS -lgcov"
fi

AM_CONDITIONAL([WITH_COVERAGE], [test "$enable_coverage" = "yes"])
AC_SUBST(LCOV)
AC_SUBST(GCOV)
AC_SUBST(GENHTML)

# ---------------------------------------------------------------------

P11KIT_LT_RELEASE=$P11KIT_CURRENT:$P11KIT_REVISION:$P11KIT_AGE
AC_SUBST(P11KIT_LT_RELEASE)

eval SHLEXT=$shrext_cmds
AC_DEFINE_UNQUOTED(SHLEXT, ["$SHLEXT"], [File extension for shared libraries])
AC_SUBST(SHLEXT)

AC_CONFIG_FILES([Makefile
	build/Makefile
	common/Makefile
	common/tests/Makefile
	doc/Makefile
	doc/version.xml
	po/Makefile.in
	p11-kit/Makefile
	p11-kit/tests/Makefile
	p11-kit/p11-kit-1.pc
	p11-kit/pkcs11.conf.example
	tools/Makefile
])
AC_OUTPUT

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
])
