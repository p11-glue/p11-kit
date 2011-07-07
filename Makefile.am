
SUBDIRS = \
	p11-kit \
	tools \
	tests \
	doc \
	po

ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-gtk-doc \
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
	mkdir -p tests/coverage
	$(LCOV) --directory . --zerocounters
	$(MAKE) check
	$(LCOV) --directory . --capture --output-file tests/coverage.info
	$(GENHTML) --output-directory tests/coverage tests/coverage.info
	@echo "file://$(abs_top_builddir)/tests/coverage/index.html"
endif

if ENABLE_GTK_DOC
upload-doc: all
	rsync -Hvax --exclude doc \
		doc/html/./ anarchy.freedesktop.org:/srv/p11-glue.freedesktop.org/www/doc/p11-kit/./
endif

upload-release: $(DIST_ARCHIVES)
	gpg --detach-sign --local-user 'stef@thewalter.net' $(DIST_ARCHIVES)
	scp $(DIST_ARCHIVES) $(DIST_ARCHIVES).sig anarchy.freedesktop.org:/srv/p11-glue.freedesktop.org/www/releases/

EXTRA_DIST = config.rpath
