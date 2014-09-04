abs_top_builddir = @abs_top_builddir@

NULL =

# We require automake 1.6 at least.
AUTOMAKE_OPTIONS = 1.6

# The name of the module, e.g. 'glib'.
DOC_MODULE=p11-kit

# The top-level SGML file. You can change this if you want to.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.xml

# The directory containing the source code. Relative to $(srcdir).
# gtk-doc will search all .c & .h files beneath here for inline comments
# documenting the functions and macros.
# e.g. DOC_SOURCE_DIR=../../../gtk
DOC_SOURCE_DIR=$(top_srcdir)/p11-kit

# Extra options to pass to gtkdoc-scangobj. Not normally needed.
SCANGOBJ_OPTIONS= --version

# Extra options to supply to gtkdoc-scan.
# e.g. SCAN_OPTIONS=--deprecated-guards="GTK_DISABLE_DEPRECATED"
SCAN_OPTIONS= --rebuild-types --deprecated-guards="P11_KIT_DISABLE_DEPRECATED"

# Extra options to supply to gtkdoc-mkdb.
# e.g. MKDB_OPTIONS=--sgml-mode --output-format=xml
MKDB_OPTIONS=--sgml-mode --output-format=xml

# Extra options to supply to gtkdoc-mktmpl
# e.g. MKTMPL_OPTIONS=--only-section-tmpl
MKTMPL_OPTIONS=

# MKHTML_OPTIONS=--path="$(builddir)/html $(srcdir)/html"

# Extra options to supply to gtkdoc-fixref. Not normally needed.
# e.g. FIXXREF_OPTIONS=--extra-dir=../gdk-pixbuf/html --extra-dir=../gdk/html
FIXXREF_OPTIONS=

# Used for dependencies. The docs will be rebuilt if any of these change.
# e.g. HFILE_GLOB=$(top_srcdir)/gtk/*.h
# e.g. CFILE_GLOB=$(top_srcdir)/gtk/*.c
HFILE_GLOB=$(top_srcdir)/p11-kit/*.h
CFILE_GLOB=$(top_srcdir)/p11-kit/*.c

# Header files to ignore when scanning.
# e.g. IGNORE_HFILES=gtkdebug.h gtkintl.h
IGNORE_HFILES= \
	private.h \
	pkcs11.h \
	conf.h \
	debug.h \
	dict.h \
	log.h \
	mock.h \
	modules.h \
	pkcs11.h \
	pkcs11i.h \
	pkcs11x.h \
	private.h \
	proxy.h \
	rpc.h \
	rpc-message.h \
	util.h \
	virtual.h \
	array.h \
	compat.h \
	$(NULL)

# Images to copy into HTML directory.
# e.g. HTML_IMAGES=$(top_srcdir)/gtk/stock-icons/stock_about_24.png
HTML_IMAGES=

generate_files= \
	version.xml \
	userdir.xml \
	sysdir.xml \
	$(NULL)

# Extra SGML files that are included by $(DOC_MAIN_SGML_FILE).
# e.g. content_files=running.sgml building.sgml changes-2.0.sgml
content_files=p11-kit-config.xml p11-kit-sharing.xml \
	p11-kit-devel.xml \
	p11-kit-proxy.xml \
	p11-kit-trust.xml \
	p11-kit.xml \
	pkcs11.conf.xml \
	trust.xml \
	annotation-glossary.xml \
	$(NULL)

# SGML files where gtk-doc abbrevations (#GtkWidget) are expanded
# These files must be listed here *and* in content_files
# e.g. expand_content_files=running.sgml
expand_content_files= $(generate_files)

# CFLAGS and LDFLAGS for compiling gtkdoc-scangobj with your library.
# Only needed if you are using gtkdoc-scangobj to dynamically query widget
# signals and properties.
# e.g. INCLUDES=-I$(top_srcdir) -I$(top_builddir) $(GTK_DEBUG_FLAGS)
# e.g. GTKDOC_LIBS=$(top_builddir)/gtk/$(gtktargetlib)
GTKDOC_LIBS=

# Hacks around gtk-doc brokenness for out of tree builds
$(builddir)/p11-kit-sections.txt: $(srcdir)/p11-kit-sections.txt
	cp $(srcdir)/p11-kit-sections.txt $(builddir)/p11-kit-sections.txt
$(builddir)/p11-kit-overrides.txt: $(srcdir)/p11-kit-overrides.txt
	cp $(srcdir)/p11-kit-overrides.txt $(builddir)/p11-kit-overrides.txt

# Generate our files with variables
sysdir.xml:
	$(AM_V_GEN) echo -n $(p11_system_config) > "$@"
userdir.xml:
	$(AM_V_GEN) echo -n $(p11_user_config) > "$@"
version.xml:
	$(AM_V_GEN) echo -n $(VERSION) > "$@"

# This includes the standard gtk-doc make rules, copied by gtkdocize.
include $(top_srcdir)/build/gtk-doc.make

if ENABLE_GTK_DOC
man1_MANS = trust.1
man8_MANS = p11-kit.8
man5_MANS = pkcs11.conf.5

XSLTPROC_FLAGS = \
        --nonet \
        --stringparam man.output.quietly 1 \
        --stringparam funcsynopsis.style ansi \
        --stringparam man.th.extra1.suppress 1 \
        --stringparam man.authors.section.enabled 0 \
        --stringparam man.copyright.section.enabled 0

XSLTPROC_MAN = \
	$(XSLTPROC) $(XSLTPROC_FLAGS) --path $(builddir) \
	http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl

trust.1: trust.xml $(generate_files)
	$(AM_V_GEN) $(XSLTPROC_MAN) $<
pkcs11.conf.5: pkcs11.conf.xml $(generate_files)
	$(AM_V_GEN) $(XSLTPROC_MAN) $<
p11-kit.8: p11-kit.xml $(generate_files)
	$(AM_V_GEN) $(XSLTPROC_MAN) $<

else # ENABLE_GTK_DOC

man1_MANS =
man5_MANS =
man8_MANS =

endif # ENABLE_GTK_DOC

MAN_IN_FILES = \
	$(man8_MANS:.8=.xml) \
	$(man5_MANS:.5=.xml) \
	$(man1_MANS:.1=.xml) \
	$(NULL)

CLEANFILES += \
	$(man1_MANS) \
	$(man5_MANS) \
	$(man8_MANS) \
	$(NULL)

EXTRA_DIST += \
	$(MAN_IN_FILES) \
	sysdir.xml \
	userdir.xml \
	version.xml \
	$(NULL)
