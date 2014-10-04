
NULL =
WEBHOST = anarchy.freedesktop.org
WEBBASE = /srv/p11-glue.freedesktop.org/www

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

CHECK_PROGS =

EXTRA_DIST = HACKING

incdir = $(includedir)/p11-kit-1/p11-kit
inc_HEADERS =

lib_LTLIBRARIES =

noinst_LTLIBRARIES =
noinst_PROGRAMS = $(CHECK_PROGS)
noinst_SCRIPTS =

TESTS = $(CHECK_PROGS)

include common/Makefile.am
include p11-kit/Makefile.am

if WITH_TRUST_MODULE
include trust/Makefile.am
endif

SUBDIRS = . doc po

ACLOCAL_AMFLAGS = -I build/m4

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-doc \
	--disable-coverage \
	--enable-strict \
	CFLAGS='-O2'


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
		  $(top_srcdir)/missing --run git log --stat --date=short ) > ChangeLog.tmp \
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

upload-coverage: coverage
	rsync -Hvax build/coverage/./ $(WEBHOST):$(WEBBASE)/build/coverage/./
endif

if ENABLE_GTK_DOC
upload-doc: all
	rsync -Hvax --exclude doc --exclude build \
		doc/manual/html/./ $(WEBHOST):$(WEBBASE)/doc/p11-kit/./
endif

upload-release: $(DIST_ARCHIVES)
	gpg --detach-sign --local-user 'stef@thewalter.net' $<
	scp $< $<.sig $(WEBHOST):$(WEBBASE)/releases/

transifex:
	cd $(srcdir) && sh build/tx-update
