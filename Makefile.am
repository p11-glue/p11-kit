
if WITH_TRUST_MODULE
TRUST_DIR = trust
else
TRUST_DIR =
endif

SUBDIRS = \
	build \
	common \
	p11-kit \
	$(TRUST_DIR) \
	tools \
	doc \
	po

ACLOCAL_AMFLAGS = -I build/m4

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-doc \
	--disable-coverage

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
	$(GENHTML) --output-directory build/coverage build/coverage.info
	@echo "file://$(abs_top_builddir)/build/coverage/index.html"
endif

if ENABLE_GTK_DOC
upload-doc: all
	rsync -Hvax --exclude doc \
		doc/html/./ anarchy.freedesktop.org:/srv/p11-glue.freedesktop.org/www/doc/p11-kit/./
endif

upload-release: $(DIST_ARCHIVES)
	gpg --detach-sign --local-user 'stef@thewalter.net' $(DIST_ARCHIVES)
	scp $(DIST_ARCHIVES) $(DIST_ARCHIVES).sig anarchy.freedesktop.org:/srv/p11-glue.freedesktop.org/www/releases/

EXTRA_DIST = \
	config.rpath \
	HACKING

transifex:
	sh build/tx-update
