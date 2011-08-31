AC_PREREQ(2.65)
AC_CONFIG_MACRO_DIR([m4])

AC_INIT([p11-kit],
	[0.5],
	[https://bugs.freedesktop.org/enter_bug.cgi?product=p11-glue],
	[p11-kit],
	[http://p11-glue.freedesktop.org/p11-kit.html])

dnl ****************************************************************************
dnl p11-kit libtool versioning
dnl CURRENT : REVISION : AGE
dnl   +1    :     0    : +1   == new interface that does not break old one.
dnl   +1    :     0    :  0   == removed an interface. Breaks old apps.
dnl    ?    :    +1    :  ?   == internal changes that doesn't break anything.

P11KIT_CURRENT=0
P11KIT_REVISION=0
P11KIT_AGE=0

dnl ****************************************************************************

AC_CONFIG_SRCDIR([p11-kit/modules.c])
AC_CONFIG_HEADERS([config.h])

dnl Other initialization
AM_INIT_AUTOMAKE([1.11])
AM_SANITY_CHECK
AM_MAINTAINER_MODE([enable])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)
LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

LINGUAS=""
AM_GNU_GETTEXT([external], [need-ngettext])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O

dnl Checks for libraries.
AC_CHECK_LIB(pthread, pthread_mutex_lock,,
	[AC_MSG_ERROR([could not find pthread_mutex_lock])])
AC_SEARCH_LIBS([dlopen], [dl dld], [],
	[AC_MSG_ERROR([could not find dlopen])])


dnl Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_MEMBERS([struct dirent.d_type],,,[#include <dirent.h>])

GTK_DOC_CHECK([1.15])

# --------------------------------------------------------------------
# PKCS#11 Directories

AC_ARG_WITH([pkcs11-dir],
            [AS_HELP_STRING([--with-pkcs11-dir], [Change PKCS#11 system config directory])],
            [pkcs11_dir=$withval],
            [pkcs11_dir=$sysconfdir/pkcs11])

# We expand these so we have concrete paths
p11_system_dir=$(eval echo $pkcs11_dir)
p11_system_conf=$(eval echo $p11_system_dir/pkcs11.conf)
p11_system_modules=$(eval echo $p11_system_dir/modules)
p11_user_conf="~/.pkcs11/pkcs11.conf"
p11_user_modules="~/.pkcs11/modules"

AC_DEFINE_UNQUOTED(P11_SYSTEM_CONF, "$p11_system_conf", [System configuration file])
AC_DEFINE_UNQUOTED(P11_SYSTEM_MODULES, "$p11_system_modules", [System modules dir])
AC_DEFINE_UNQUOTED(P11_USER_CONF, "$p11_user_conf", [User configuration file])
AC_DEFINE_UNQUOTED(P11_USER_MODULES, "$p11_user_modules", [User modules dir])

AC_SUBST(p11_system_dir)
AC_SUBST(p11_system_conf)
AC_SUBST(p11_system_modules)
AC_SUBST(p11_user_conf)
AC_SUBST(p11_user_modules)

# --------------------------------------------------------------------
# Warnings to show if using GCC

AC_ARG_ENABLE(more-warnings,
	      AS_HELP_STRING([--disable-more-warnings], [Inhibit compiler warnings]),
	      set_more_warnings=no)

if test "$GCC" = "yes" -a "$set_more_warnings" != "no"; then
	CFLAGS="$CFLAGS \
		-Wall -Wstrict-prototypes -Wmissing-declarations \
		-Wmissing-prototypes -Wnested-externs -Wpointer-arith \
		-Wdeclaration-after-statement -Wformat=2 -Winit-self \
		-Waggregate-return -Wno-missing-format-attribute"

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
fi

# ----------------------------------------------------------------------
# Coverage

AC_MSG_CHECKING([whether to build with gcov testing])
AC_ARG_ENABLE([coverage],
		AS_HELP_STRING([--enable-coverage],
			[Whether to enable coverage testing ]),
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
# Debug mode

AC_ARG_ENABLE(debug,
              AS_HELP_STRING([--enable-debug=no/yes/full],[Turn on or off debugging]))

if test "$enable_debug" != "no"; then
	AC_DEFINE_UNQUOTED(WITH_DEBUG, 1, [Print debug output])
fi

if test "$enable_debug" = "full"; then
	debug_status="full"
	CFLAGS="$CFLAGS -g -O0 -Werror"

elif test "$enable_debug" = "no"; then
	debug_status="no"
	AC_DEFINE_UNQUOTED(NDEBUG, 1, [Disable glib assertions])

else
	debug_status="yes"
fi


# ---------------------------------------------------------------------

P11KIT_LT_RELEASE=$P11KIT_CURRENT:$P11KIT_REVISION:$P11KIT_AGE
AC_SUBST(P11KIT_LT_RELEASE)

AC_CONFIG_FILES([Makefile
	doc/Makefile
	doc/version.xml
	po/Makefile.in
	p11-kit/Makefile
	p11-kit/p11-kit-1.pc
	p11-kit/pkcs11.conf.example
	tests/Makefile
	tools/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([build options:

    System Global Config:     $p11_system_conf
    User Global Config:       $p11_user_conf
    System Module Directory:  $p11_system_modules
    User Module Directory:    $p11_user_modules
])
