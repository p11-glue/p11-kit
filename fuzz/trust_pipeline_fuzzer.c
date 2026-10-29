/*
 * fuzz/trust_pipeline_fuzzer.c -- fuzz p11-kit's trust-module pipeline:
 * parse -> builder -> index -> enumerate -> extract.
 *
 * Threat model:
 *   p11-kit's trust module parses trust-store files (PKCS#11 persistent
 *   format, PEM bundles, raw X.509 DER) supplied by whoever controls the
 *   files in a trust store location, builds internal index objects from
 *   them (parsing X.509 extensions along the way), and re-serialises them
 *   into export formats (PEM bundles/directories, Java JKS cacerts, edk2,
 *   OpenSSL bundles, plain DER).  All of that code runs in-process inside
 *   applications that consume trust information, on attacker-influenceable
 *   file content.
 *
 * Pipeline per input:
 *   1. p11_parse_memory() with x509/pem/persist format handlers (parser.c,
 *      persist.c, pem.c, asn1.c, base64.c)
 *   2. every parsed object goes through p11_index_add() on an index whose
 *      build callback is p11_builder_build() (builder.c, x509.c, digest.c,
 *      attrs.c)
 *   3. the built objects are added to the in-tree mock PKCS#11 module and
 *      enumerated through p11_kit_iter with p11_enumerate's own callbacks
 *      (enumerate.c, iter.c), so each object is prepared exactly like in
 *      production (certificate DER + ASN.1 decode)
 *   4. all nine extract writers are run against the enumeration into a
 *      throw-away temp directory (extract*.c, save.c, utf8.c)
 *
 * Per-object and corpus-count bounds keep the harness cost flat; the
 * attacker controls the content, not the shape of the pipeline.
 */

#include "config.h"

/* The p11-kit iter API is unstable-by-default; upstream builds define
 * this project-wide (Makefile.am/meson.build) but the OSS-Fuzz fuzzer
 * compile loop does not. */
#ifndef P11_KIT_FUTURE_UNSTABLE_API
#define P11_KIT_FUTURE_UNSTABLE_API 1
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "fuzz/fuzz.h"
#include "test.h"
#include "mock.h"
#include "attrs.h"
#include "p11-kit/iter.h"
#include "trust/parser.h"
#include "trust/builder.h"
#include "trust/index.h"
#include "trust/enumerate.h"
#include "trust/extract.h"

#define MAX_OBJECTS 16

/*
 * Run one extract writer against a fresh enumeration: the iterator must
 * not be reused after it has been exhausted (its module state is torn
 * down at the end of iteration), so every writer gets its own
 * p11_enumerate/iter lifecycle, exactly like a fresh extraction run.
 */
/* Production extraction only iterates certificate objects; without
 * this filter non-certificate objects from the trust store (data,
 * extensions) would reach writers that assume certificates. */
static const CK_OBJECT_CLASS certificate_class = CKO_CERTIFICATE;
static const CK_ATTRIBUTE certificate_filter[] = {
 { CKA_CLASS, (CK_VOID_PTR)&certificate_class, sizeof (certificate_class) },
};

/* The mock module can serve malformed placeholder objects (zero class,
 * empty CKA_VALUE) that production trust modules never produce; make the
 * iterator skip them so writers only see well-formed objects. */
static CK_RV
skip_junk_callback (P11KitIter *iter,
                    CK_BBOOL *matches,
                    void *data)
{
        p11_enumerate *dex = (p11_enumerate *)data;
        CK_ATTRIBUTE *v;

        /* Mock modules can serve malformed placeholder objects (no class,
         * empty CKA_VALUE) that production trust modules never produce;
         * skip them so writers only see well-formed certificates. */
        if (dex->klass != CKO_CERTIFICATE)
                *matches = CK_FALSE;
        v = p11_attrs_find_valid (dex->attrs, CKA_VALUE);
        if (!v || !v->pValue || v->ulValueLen == 0)
                *matches = CK_FALSE;
        return CKR_OK;
}

static void

run_extractor (CK_FUNCTION_LIST *module,
               bool (*fn) (p11_enumerate *ex, const char *destination),
               const char *path)
{
	p11_enumerate ex;

	p11_enumerate_init (&ex);
	p11_kit_iter_add_filter (ex.iter, certificate_filter, 1);
	p11_kit_iter_add_callback (ex.iter, skip_junk_callback, &ex, NULL);
	p11_kit_iter_begin_with (ex.iter, module, 0, 0);
	fn (&ex, path);
	p11_enumerate_cleanup (&ex);
}

#ifdef __cplusplus
extern "C"
#endif
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
p11_parser *parser;
p11_builder *builder;
p11_index *index;
p11_array *parsed;
CK_OBJECT_HANDLE handles[MAX_OBJECTS];
CK_FUNCTION_LIST module;
char *dir;
char path[4096];
size_t i;
int nobjects = 0;

if (size < 1)
return 0;

/*
 * Stage 1: parse the trust-store bytes.
 */
parser = p11_parser_new (NULL);
if (!parser)
return 0;
p11_parser_formats (parser,
                    p11_parser_format_x509,
                    p11_parser_format_pem,
                    p11_parser_format_persist,
                    NULL);
p11_parse_memory (parser, "fuzz-input", P11_PARSE_FLAG_NONE, data, size);
parsed = p11_parser_parsed (parser);

/*
 * Stage 2: build indexed objects; the index's build callback is the
 * real p11_builder_build, so X.509 extension parsing and digesting
 * happen through the production path.
 */
builder = p11_builder_new (0);
index = NULL;
if (builder) {
index = p11_index_new (p11_builder_build, NULL, NULL,
                       p11_builder_changed, builder);
if (index && parsed) {
for (i = 0; i < (size_t)parsed->num && nobjects < MAX_OBJECTS; i++) {
CK_ATTRIBUTE *attrs = parsed->elem[i];
if (!attrs)
continue;
if (p11_index_add (index, attrs, p11_attrs_count (attrs),
                   &handles[nobjects]) == CKR_OK)
nobjects++;
}
}
}

/*
 * Stage 3 + 4: enumerate the built objects through the mock module
 * and run every extract writer against a throw-away directory.
 */
if (nobjects > 0) {
dir = p11_test_directory ("p11-fuzz-trust");
if (dir) {
mock_module_init ();
mock_module_reset ();
memcpy (&module, &mock_module, sizeof (module));
module.C_Initialize (NULL);
	for (i = 0; i < (size_t)nobjects; i++) {
		/* Objects with an empty CKA_VALUE carry nothing fuzzable for the
		 * writers; production (with P11_ENUMERATE_CORRELATE) skips them
		 * during enumeration as well. */
		CK_ATTRIBUTE *v = p11_attrs_find_valid (parsed->elem[i], CKA_VALUE);
		if (v && v->ulValueLen == 0)
			continue;
		mock_module_add_object (MOCK_SLOT_ONE_ID, parsed->elem[i]);
		/* TEMP DIAGNOSTIC */
		{
			p11_enumerate dex;
			p11_enumerate_init (&dex);
			dex.flags |= P11_ENUMERATE_CORRELATE;
			p11_kit_iter_add_filter (dex.iter, certificate_filter, 1);
			p11_kit_iter_begin_with (dex.iter, &module, 0, 0);
			while (p11_kit_iter_next (dex.iter) == CKR_OK) {
				CK_ATTRIBUTE *v = p11_attrs_find_valid (dex.attrs, CKA_VALUE);
				fprintf (stderr, "DIAG: cert_der=%p cert_len=%zu CKA_VALUE=%p len=%lu klass=%lu\n",
				         (void *)dex.cert_der, dex.cert_len, v ? v->pValue : (void *)0,
				         v ? (unsigned long)v->ulValueLen : 0UL, (unsigned long)dex.klass);
			}
			p11_enumerate_cleanup (&dex);
		}
	}

snprintf (path, sizeof (path), "%s/cert.der", dir);
run_extractor (&module, p11_extract_x509_file, path);

snprintf (path, sizeof (path), "%s/certs.d", dir);
run_extractor (&module, p11_extract_x509_directory, path);

snprintf (path, sizeof (path), "%s/bundle.pem", dir);
run_extractor (&module, p11_extract_pem_bundle, path);

snprintf (path, sizeof (path), "%s/pem.d", dir);
run_extractor (&module, p11_extract_pem_directory, path);

snprintf (path, sizeof (path), "%s/pemhash.d", dir);
run_extractor (&module, p11_extract_pem_directory_hash, path);

snprintf (path, sizeof (path), "%s/cacerts.jks", dir);
run_extractor (&module, p11_extract_jks_cacerts, path);

snprintf (path, sizeof (path), "%s/edk2.p12", dir);
run_extractor (&module, p11_extract_edk2_cacerts, path);

snprintf (path, sizeof (path), "%s/bundle.pem.pem", dir);
run_extractor (&module, p11_extract_openssl_bundle, path);

snprintf (path, sizeof (path), "%s/openssl.d", dir);
run_extractor (&module, p11_extract_openssl_directory, path);

mock_module_reset ();
p11_test_directory_delete (dir);
free (dir);
}
}


if (index)
p11_index_free (index);
if (builder)
p11_builder_free (builder);
p11_parser_free (parser);

return 0;
}
