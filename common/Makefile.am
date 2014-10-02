
inc_HEADERS += \
	common/pkcs11.h \
	common/pkcs11x.h \
	$(NULL)

noinst_LTLIBRARIES += \
	libp11-common.la \
	libp11-library.la \
	libp11-test.la \
	libp11-tool.la \
	$(NULL)

libp11_common_la_SOURCES = \
	common/argv.c common/argv.h \
	common/attrs.c common/attrs.h \
	common/array.c common/array.h \
	common/buffer.c common/buffer.h \
	common/compat.c common/compat.h \
	common/constants.c common/constants.h \
	common/debug.c common/debug.h \
	common/dict.c common/dict.h \
	common/hash.c common/hash.h \
	common/lexer.c common/lexer.h \
	common/message.c common/message.h \
	common/path.c common/path.h \
	common/pkcs11.h common/pkcs11x.h common/pkcs11i.h \
	common/url.c common/url.h \
	$(NULL)

libp11_library_la_SOURCES = \
	common/library.c common/library.h \
	$(NULL)

libp11_test_la_SOURCES = \
	common/mock.c common/mock.h \
	common/test.c common/test.h \
	$(NULL)

libp11_tool_la_SOURCES = \
	common/tool.c common/tool.h \
	$(NULL)

# Tests ----------------------------------------------------------------

common_LIBS = \
	libp11-test.la \
	libp11-common.la \
	$(NULL)

CHECK_PROGS += \
	test-tests \
	test-compat \
	test-hash \
	test-dict \
	test-array \
	test-constants \
	test-attrs \
	test-buffer \
	test-url \
	test-path \
	test-lexer \
	test-message \
	$(NULL)

test_array_SOURCES = common/test-array.c
test_array_LDADD = $(common_LIBS)

test_attrs_SOURCES = common/test-attrs.c
test_attrs_LDADD = $(common_LIBS)

test_buffer_SOURCES = common/test-buffer.c
test_buffer_LDADD = $(common_LIBS)

test_compat_SOURCES = common/test-compat.c
test_compat_LDADD = $(common_LIBS)

test_constants_SOURCES = common/test-constants.c
test_constants_LDADD = $(common_LIBS)

test_dict_SOURCES = common/test-dict.c
test_dict_LDADD = $(common_LIBS)

test_hash_SOURCES = common/test-hash.c
test_hash_LDADD = $(common_LIBS)

test_lexer_SOURCES = common/test-lexer.c
test_lexer_LDADD = $(common_LIBS)

test_message_SOURCES = common/test-message.c
test_message_LDADD = $(common_LIBS)

test_path_SOURCES = common/test-path.c
test_path_LDADD = $(common_LIBS)

test_tests_SOURCES = common/test-tests.c
test_tests_LDADD = $(common_LIBS)

test_url_SOURCES = common/test-url.c
test_url_LDADD = $(common_LIBS)

noinst_PROGRAMS += \
	frob-getauxval \
	frob-getenv \
	$(NULL)

frob_getauxval_SOURCES = common/frob-getauxval.c
frob_getauxval_LDADD = $(common_LIBS)

frob_getenv_SOURCES = common/frob-getenv.c
frob_getenv_LDADD = $(common_LIBS)
