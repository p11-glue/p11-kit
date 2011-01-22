AC_PREREQ(2.65)
AC_CONFIG_MACRO_DIR([m4])

AC_INIT([p11-unity],[0.1],[http://bugzilla.example.com])

AC_CONFIG_SRCDIR([module/p11-unity.c])
AC_CONFIG_HEADERS([config.h])

dnl Other initialization
AM_INIT_AUTOMAKE
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
		])
AC_OUTPUT

