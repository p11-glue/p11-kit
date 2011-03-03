
# 	p11-kit-glue.xml

PARTS = \
	p11-kit-config.xml \
	p11-kit-multiple-problem.xml

BOOK = \
	p11-kit.xml

DOCUMENTS = \
	html/p11-kit.html

all-local: $(DOCUMENTS)

html/p11-kit.html: $(BOOK) $(PARTS)
	xmlto --skip-validation -vv html-nochunks -o html/ p11-kit.xml

EXTRA_DIST = \
	$(BOOK) \
	$(PARTS) \
	docbook-params.xsl
