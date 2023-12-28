/*
 * Copyright (c) 2023, Red Hat Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Author: Zoltan Fridrich <zfridric@redhat.com>
 */

#include "config.h"

#include "attrs.h"
#include "compat.h"
#include "debug.h"
#include "dict.h"
#include "iter.h"
#include "message.h"
#include "pem.h"
#include "options.h"
#include "tool.h"

#ifdef WITH_ASN1
#include "asn1.h"
#include "oid.h"
#endif

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

int
p11_kit_import_object (int argc,
		       char *argv[]);

#ifdef WITH_ASN1

typedef struct {
	bool parse_error;
	p11_dict *defs;
	CK_FUNCTION_LIST *module;
	CK_SESSION_HANDLE session;
	const char *label;
} import_data;

static bool
import_x509_cert (const unsigned char *der,
		  size_t der_len,
		  const import_data *data)
{
	bool ok = false;
	int start = 0, end = 0;
	CK_RV rv;
	asn1_node asn = NULL;
	CK_OBJECT_HANDLE object = 0;
	CK_ATTRIBUTE *attrs = NULL, *tmp = NULL;
	CK_BBOOL tval = CK_TRUE, fval = CK_FALSE;
	CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
	CK_ATTRIBUTE attr_class = { CKA_CLASS, &class, sizeof (class) };
	CK_ATTRIBUTE attr_token = { CKA_TOKEN, &tval, sizeof (tval) };
	CK_ATTRIBUTE attr_private = { CKA_PRIVATE, &fval, sizeof (fval) };
	CK_ATTRIBUTE attr_cert_type = { CKA_CERTIFICATE_TYPE, &cert_type, sizeof (cert_type) };
	CK_ATTRIBUTE attr_value = { CKA_VALUE, (void *)der, der_len };
	CK_ATTRIBUTE attr_subject = { CKA_SUBJECT, };

	return_val_if_fail (data != NULL, false);
	return_val_if_fail (data->module != NULL, false);

	asn = p11_asn1_decode (data->defs, "PKIX1.Certificate", der, der_len, NULL);
	if (asn == NULL) {
		p11_message (_("failed to parse ASN.1 structure"));
		goto cleanup;
	}

	if (asn1_der_decoding_startEnd (asn, der, der_len, "tbsCertificate.subject",
					&start, &end) != ASN1_SUCCESS) {
		p11_message (_("failed to obtain certificate subject name"));
		goto cleanup;
	}
	attr_subject.pValue = (void *)(der + start);
	attr_subject.ulValueLen = end - start + 1;

	attrs = p11_attrs_build (NULL, &attr_class, &attr_token, &attr_private,
				 &attr_cert_type, &attr_value, &attr_subject, NULL);
	if (attrs == NULL) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	if (data->label != NULL) {
		CK_ATTRIBUTE attr_label = { CKA_LABEL, (void *)data->label, strlen (data->label) };

		tmp = p11_attrs_build (attrs, &attr_label, NULL);
		if (tmp == NULL) {
			p11_message (_("failed to allocate memory"));
			goto cleanup;
		}
		attrs = tmp;
	}

	rv = data->module->C_CreateObject (data->session, attrs, p11_attrs_count (attrs), &object);
	if (rv != CKR_OK) {
		p11_message (_("failed to create object: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	ok = true;

cleanup:
	p11_attrs_free (attrs);
	p11_asn1_free (asn);

	return ok;
}

static CK_ATTRIBUTE *
init_attrs_pubkey (const unsigned char *info,
		   size_t info_len,
		   const import_data *data)
{
	CK_ATTRIBUTE *attrs = NULL, *tmp = NULL;
	CK_BBOOL tval = CK_TRUE, fval = CK_FALSE;
	CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE attr_class = { CKA_CLASS, &class, sizeof (class) };
	CK_ATTRIBUTE attr_token = { CKA_TOKEN, &tval, sizeof (tval) };
	CK_ATTRIBUTE attr_private = { CKA_PRIVATE, &fval, sizeof (fval) };
	CK_ATTRIBUTE attr_verify = { CKA_VERIFY, &tval, sizeof (tval) };
	CK_ATTRIBUTE attr_info = { CKA_PUBLIC_KEY_INFO, (void *)info, info_len };

	return_val_if_fail (data != NULL, NULL);

	attrs = p11_attrs_build (NULL, &attr_class, &attr_token, &attr_private,
				 &attr_verify, &attr_info, NULL);
	if (attrs == NULL)
		return NULL;

	if (data->label != NULL) {
		CK_ATTRIBUTE attr_label = { CKA_LABEL, (void *)data->label, strlen (data->label) };

		tmp = p11_attrs_build (attrs, &attr_label, NULL);
		if (tmp == NULL) {
			p11_attrs_free (attrs);
			return NULL;
		}
		attrs = tmp;
	}

	return attrs;
}

static CK_ATTRIBUTE *
add_attrs_pubkey_rsa (CK_ATTRIBUTE *attrs,
		      asn1_node info,
		      p11_dict *defs)
{
	unsigned char *pubkey = NULL;
	size_t pubkey_len = 0;
	asn1_node asn = NULL;
	CK_ATTRIBUTE *result = NULL;
	CK_BBOOL tval = CK_TRUE;
	CK_KEY_TYPE key_type = CKK_RSA;
	CK_ATTRIBUTE attr_key_type = { CKA_KEY_TYPE, &key_type, sizeof (key_type) };
	CK_ATTRIBUTE attr_encrypt = { CKA_ENCRYPT, &tval, sizeof (tval) };
	CK_ATTRIBUTE attr_modulus = { CKA_MODULUS, };
	CK_ATTRIBUTE attr_exponent = { CKA_PUBLIC_EXPONENT, };
	size_t len = 0;

	pubkey = p11_asn1_read (info, "subjectPublicKey", &pubkey_len);
	if (pubkey == NULL) {
		p11_message (_("failed to obtain subject public key data"));
		goto cleanup;
	}

	pubkey_len = p11_asn1_tlv_length (pubkey, pubkey_len);
	if ((ssize_t)pubkey_len == -1) {
		p11_message (_("failed to parse ASN.1 structure"));
		goto cleanup;
	}

	asn = p11_asn1_decode (defs, "PKIX1.RSAPublicKey", pubkey, pubkey_len, NULL);
	if (asn == NULL) {
		p11_message (_("failed to parse ASN.1 structure"));
		goto cleanup;
	}

	attr_modulus.pValue = p11_asn1_read (asn, "modulus", &len);
	if (attr_modulus.pValue == NULL) {
		p11_message (_("failed to obtain modulus"));
		goto cleanup;
	}
#if ULONG_MAX < SIZE_MAX
	if (len > ULONG_MAX) {
		p11_message (_("failed to obtain modulus"));
		goto cleanup;
	}
#endif
	attr_modulus.ulValueLen = len;

	attr_exponent.pValue = p11_asn1_read (asn, "publicExponent", &len);
	if (attr_exponent.pValue == NULL) {
		p11_message (_("failed to obtain exponent"));
		goto cleanup;
	}
#if ULONG_MAX < SIZE_MAX
	if (len > ULONG_MAX) {
		p11_message (_("failed to obtain exponent"));
		goto cleanup;
	}
#endif
	attr_exponent.ulValueLen = len;

	result = p11_attrs_build (attrs, &attr_key_type, &attr_encrypt, &attr_modulus, &attr_exponent, NULL);
	if (result == NULL) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

cleanup:
	free (attr_modulus.pValue);
	free (attr_exponent.pValue);
	free (pubkey);
	p11_asn1_free (asn);

	return result;
}

static CK_ATTRIBUTE *
add_attrs_pubkey_ec (CK_ATTRIBUTE *attrs,
		     asn1_node info)
{
	unsigned char *ec_point = NULL;
	size_t ec_point_len = 0;
	unsigned char ec_point_tl[ASN1_MAX_TL_SIZE];
	unsigned int ec_point_tl_len = sizeof (ec_point_tl);
	CK_ATTRIBUTE *result = NULL;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_ATTRIBUTE attr_key_type = { CKA_KEY_TYPE, &key_type, sizeof (key_type) };
	CK_ATTRIBUTE attr_ec_params = { CKA_EC_PARAMS, };
	CK_ATTRIBUTE attr_ec_point = { CKA_EC_POINT, };
	size_t len = 0;

	attr_ec_params.pValue = p11_asn1_read (info, "algorithm.parameters", &len);
	if (attr_ec_params.pValue == NULL) {
		p11_message (_("failed to obtain EC parameters"));
		goto cleanup;
	}
#if ULONG_MAX < SIZE_MAX
	if (len > ULONG_MAX) {
		p11_message (_("failed to obtain EC parameters"));
		goto cleanup;
	}
#endif
	attr_ec_params.ulValueLen = len;

	/* subjectPublicKey is read as BIT STRING value which contains
	 * EC point data. We need to DER encode this data as OCTET STRING.
	 */
	ec_point = p11_asn1_read (info, "subjectPublicKey", &ec_point_len);
	if (ec_point == NULL) {
		p11_message (_("failed to obtain EC point"));
		goto cleanup;
	}

	/* Length of a BIT STRING value is represented in bits.
	 * As the EC point is an OCTET STRING it has to be divisible by 8
	 */
	if (ec_point_len % 8 != 0) {
		p11_message (_("corrupted EC point value"));
		goto cleanup;
	}
	ec_point_len /= 8;

	if (asn1_encode_simple_der (ASN1_ETYPE_OCTET_STRING, ec_point, ec_point_len,
				    ec_point_tl, &ec_point_tl_len) != ASN1_SUCCESS) {
		p11_message (_("failed to DER encode EC point"));
		goto cleanup;
	}

	attr_ec_point.ulValueLen = ec_point_tl_len + ec_point_len;
	attr_ec_point.pValue = malloc (attr_ec_point.ulValueLen);
	if (attr_ec_point.pValue == NULL) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}
	memcpy (attr_ec_point.pValue, ec_point_tl, ec_point_tl_len);
	memcpy ((char *)attr_ec_point.pValue + ec_point_tl_len, ec_point, ec_point_len);

	result = p11_attrs_build (attrs, &attr_key_type, &attr_ec_params, &attr_ec_point, NULL);
	if (result == NULL) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

cleanup:
	free (attr_ec_params.pValue);
	free (attr_ec_point.pValue);
	free (ec_point);

	return result;
}

static bool
import_pubkey (const unsigned char *der,
	       size_t der_len,
	       const import_data *data)
{
	bool ok = false;
	char *oid = NULL;
	size_t oid_len = 0;
	CK_RV rv;
	CK_OBJECT_HANDLE object = 0;
	CK_ATTRIBUTE *attrs = NULL, *tmp = NULL;
	asn1_node asn = NULL;

	return_val_if_fail (data != NULL, false);
	return_val_if_fail (data->module != NULL, false);

	asn = p11_asn1_decode (data->defs, "PKIX1.SubjectPublicKeyInfo", der, der_len, NULL);
	if (asn == NULL) {
		p11_message (_("failed to parse ASN.1 structure"));
		goto cleanup;
	}

	oid = p11_asn1_read (asn, "algorithm.algorithm", &oid_len);
	if (oid == NULL) {
		p11_message (_("failed to obtain algorithm OID"));
		goto cleanup;
	}

	attrs = init_attrs_pubkey (der, der_len, data);
	if (attrs == NULL) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	if (strcmp (oid, P11_OID_PKIX1_RSA_STR) == 0)
		tmp = add_attrs_pubkey_rsa (attrs, asn, data->defs);
	else if (strcmp (oid, P11_OID_PKIX1_EC_STR) == 0)
		tmp = add_attrs_pubkey_ec (attrs, asn);
	else {
		p11_message (_("unrecognized algorithm OID: %s"), oid);
		goto cleanup;
	}
	if (tmp == NULL)
		goto cleanup;
	attrs = tmp;

	rv = data->module->C_CreateObject (data->session, attrs, p11_attrs_count (attrs), &object);
	if (rv != CKR_OK) {
		p11_message (_("failed to create object: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	ok = true;

cleanup:
	free (oid);
	p11_attrs_free (attrs);
	p11_asn1_free (asn);

	return ok;
}

static void
import_pem (const char *type,
	    const unsigned char *der,
	    size_t der_len,
	    void *user_data)
{
	bool ok = false;
	import_data *data = user_data;

	return_if_fail (type != NULL);
	return_if_fail (data != NULL);

	if (strcmp (type, "CERTIFICATE") == 0)
		ok = import_x509_cert (der, der_len, data);
	else if (strcmp (type, "PUBLIC KEY") == 0)
		ok = import_pubkey (der, der_len, data);
	else
		p11_message (_("unrecognized PEM label: %s"), type);
	if (!ok)
		data->parse_error = true;
}

static int
import_object (p11_tool *tool,
	       const char *file,
	       const char *label)
{
	int ret = 1;
	void *data = NULL;
	size_t data_len = 0;
	unsigned n_parsed = 0;
	CK_RV rv;
	p11_mmap *mmap = NULL;
	P11KitIter *iter = NULL;
	import_data user_data = { false, NULL, NULL, 0, label };

	iter = p11_tool_begin_iter (tool, P11_KIT_ITER_WANT_WRITABLE | P11_KIT_ITER_WITH_SESSIONS | P11_KIT_ITER_WITHOUT_OBJECTS);
	if (iter == NULL) {
		p11_message (_("failed to initialize iterator"));
		return 1;
	}

	rv = p11_kit_iter_next (iter);
	if (rv != CKR_OK) {
		if (rv == CKR_CANCEL)
			p11_message (_("no matching token"));
		else
			p11_message (_("failed to find token: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	user_data.module = p11_kit_iter_get_module (iter);
	return_val_if_fail (user_data.module != NULL, 1);
	user_data.session = p11_kit_iter_get_session (iter);
	return_val_if_fail (user_data.session != CK_INVALID_HANDLE, 1);

	user_data.defs = p11_asn1_defs_load ();
	if (user_data.defs == NULL) {
		p11_message (_("failed to load ASN.1 definitions"));
		goto cleanup;
	}

	mmap = p11_mmap_open (file, NULL, &data, &data_len);
	if (mmap == NULL) {
		p11_message (_("failed to read file: %s"), file);
		goto cleanup;
	}

	n_parsed = p11_pem_parse (data, data_len, import_pem, &user_data);
	if (n_parsed == 0) {
		p11_message (_("no object to import"));
		goto cleanup;
	}
	if (user_data.parse_error)
		goto cleanup;

	ret = 0;

cleanup:
	p11_tool_end_iter (tool, iter);
	p11_dict_free (user_data.defs);
	if (mmap != NULL)
		p11_mmap_close (mmap);

	return ret;
}

int
p11_kit_import_object (int argc,
		       char *argv[])
{
	int opt, ret = 2;
	char *label = NULL;
	char *file = NULL;
	bool login = false;
	p11_tool *tool = NULL;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
		opt_label = 'L',
		opt_file = 'f',
		opt_login = 'l',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ "label", required_argument, NULL, opt_label },
		{ "file", required_argument, NULL, opt_file },
		{ "login", no_argument, NULL, opt_login },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit import-object --file=<file.pem>"
		     " [--label=<label>] [--login] pkcs11:token" },
		{ opt_label, "label to be associated with imported object" },
		{ opt_file, "object data to import" },
		{ opt_login, "login to the token" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_label:
			label = optarg;
			break;
		case opt_file:
			file = optarg;
			break;
		case opt_login:
			login = true;
			break;
		case opt_verbose:
			p11_kit_be_loud ();
			break;
		case opt_quiet:
			p11_kit_be_quiet ();
			break;
		case opt_help:
			p11_tool_usage (usages, options);
			return 0;
		case '?':
			return 2;
		default:
			assert_not_reached ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		p11_tool_usage (usages, options);
		return 2;
	}

	if (file == NULL) {
		p11_message (_("no file specified"));
		return 2;
	}

	tool = p11_tool_new ();
	if (!tool) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	if (p11_tool_set_uri (tool, *argv, P11_KIT_URI_FOR_TOKEN) != P11_KIT_URI_OK) {
		p11_message (_("failed to parse URI"));
		goto cleanup;
	}

	p11_tool_set_login (tool, login);

	ret = import_object (tool, file, label);

 cleanup:
	p11_tool_free (tool);

	return ret;
}

#else /* WITH_ASN1 */

int
p11_kit_import_object (int argc,
		       char *argv[])
{
	p11_message (_("ASN.1 support is not compiled in"));
	return 2;
}

#endif /* !WITH_ASN1 */
