AC_PREREQ(2.65)
AC_CONFIG_MACRO_DIR([m4])

AC_INIT([p11-kit],[0.1],[http://bugzilla.example.com])

AC_CONFIG_SRCDIR([module/p11-kit-lib.c])
AC_CONFIG_HEADERS([config.h])

dnl Other initialization
AM_INIT_AUTOMAKE
AM_SANITY_CHECK
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)
LT_INIT

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O

dnl Checks for libraries.
AC_CHECK_LIB(pthread, pthread_mutex_lock,,
	[AC_MSG_ERROR([could not find pthread_mutex_lock])])
AC_CHECK_LIB(dl, dlopen,,
	[AC_MSG_ERROR([could not find dlopen])])


dnl Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_MEMBERS([struct dirent.d_type],,,[#include <dirent.h>])

# --------------------------------------------------------------------
# PAM Module Directory

AC_ARG_WITH([pkcs11-dir],
            [AC_HELP_STRING([--with-pkcs11-dir=DIR],
                            [directory which holds pkcs11 modules])],
            [], [with_pkcs11_dir='${libdir}/pkcs11'])
PKCS11_MODULE_PATH="$with_pkcs11_dir"
AC_SUBST(PKCS11_MODULE_PATH)

AM_CONDITIONAL(WITH_PAM, test "$have_pam" = "yes")

if test "$have_pam" = "yes"; then
	pam_status="yes ($with_pam_dir)"
fi

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
              AC_HELP_STRING([--enable-debug],
              [Compile binaries in debug mode]))

if test "$enable_debug" = "yes"; then
	CFLAGS="$CFLAGS -g -O0"
	AC_DEFINE_UNQUOTED(_DEBUG, 1, [In debug mode])
	echo "enabling debug compile mode"
fi

# ---------------------------------------------------------------------

AC_CONFIG_FILES([Makefile
		module/Makefile
		tests/Makefile
		])
AC_OUTPUT

