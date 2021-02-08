
NULL =

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/common \
	-DBINDIR=\"$(bindir)\" \
	-DBUILDDIR=\"$(abs_builddir)\" \
	-DDATA_DIR=\"$(datadir)\" \
	-DPRIVATEDIR=\"$(privatedir)\" \
	-DSRCDIR=\"$(abs_srcdir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DP11_KIT_FUTURE_UNSTABLE_API

bin_PROGRAMS =
private_PROGRAMS =
check_PROGRAMS = $(c_tests)
check_SCRIPTS = $(sh_tests)
check_LTLIBRARIES =

SUFFIXES =

BUILT_SOURCES =

CLEANFILES =

EXTRA_DIST = CONTRIBUTING.md meson.build meson_options.txt po/meson.build \
	doc/manual/meson.build doc/manual/userdir.xml.in \
	doc/manual/sysdir.xml.in doc/manual/version.xml.in \
	bash-completion

incdir = $(includedir)/p11-kit-1/p11-kit
inc_HEADERS =

lib_LTLIBRARIES =

noinst_LTLIBRARIES =
noinst_PROGRAMS =
noinst_SCRIPTS =

c_tests =
sh_tests =
TESTS = $(c_tests) $(sh_tests)

moduledir = $(p11_module_path)
module_LTLIBRARIES =

bashcomp_DATA =

include common/Makefile.am
include p11-kit/Makefile.am
include fuzz/Makefile.am

if WITH_TRUST_MODULE
include trust/Makefile.am
endif

SUBDIRS = . doc po

ACLOCAL_AMFLAGS = -I build/m4

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-doc \
	--without-systemd \
	--without-bash-completion \
	--disable-coverage \
	--enable-strict \
	CFLAGS='-O2'

AM_TESTS_ENVIRONMENT = \
	abs_top_builddir="$(abs_top_builddir)"; \
	export abs_top_builddir; \
	P11_MODULE_PATH="$(abs_top_builddir)/.libs"; \
	export P11_MODULE_PATH;
AM_TESTS_FD_REDIRECT = 9>&2;

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/build/litter/tap-driver.sh
LOG_DRIVER_FLAGS = --comments --ignore-exit

MEMCHECK_ENV = $(TEST_RUNNER) valgrind --error-exitcode=80 --quiet

LEAKCHECK_ENV = $(TEST_RUNNER) valgrind --error-exitcode=81 --quiet --leak-check=yes

HELLCHECK_ENV = $(TEST_RUNNER) valgrind --error-exitcode=82 --quiet --tool=helgrind

memcheck: all
	make $(AM_MAKEFLAGS) TESTS_ENVIRONMENT="$(MEMCHECK_ENV)" check-TESTS

leakcheck: all
	make $(AM_MAKEFLAGS) TESTS_ENVIRONMENT="$(LEAKCHECK_ENV)" check-TESTS

hellcheck: all
	make $(AM_MAKEFLAGS) TESTS_ENVIRONMENT="$(HELLCHECK_ENV)" check-TESTS

dist-hook:
	@if test -d "$(srcdir)/.git"; \
	then \
		echo Creating ChangeLog && \
		( cd "$(top_srcdir)" && \
		  echo '# Generate automatically. Do not edit.'; echo; \
		  $(top_srcdir)/build/litter/missing --run git log --stat --date=short ) > ChangeLog.tmp \
		&& mv -f ChangeLog.tmp $(top_distdir)/ChangeLog \
		|| ( rm -f ChangeLog.tmp ; \
		     echo Failed to generate ChangeLog >&2 ); \
	else \
		echo A git clone is required to generate a ChangeLog >&2; \
	fi

if WITH_COVERAGE
coverage:
	mkdir -p build/coverage
	$(LCOV) --directory . --zerocounters
	$(MAKE) check
	$(LCOV) --directory . --capture --output-file build/coverage.info
	$(GENHTML) --output-directory build/coverage \
		--title "p11-kit $(PACKAGE_VERSION)" \
		build/coverage.info
	@echo "file://$(abs_top_builddir)/build/coverage/index.html"
endif

transifex:
	cd $(srcdir) && sh build/tx-update
