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
 * Author: Zoltan Fridrich <zfridric@redhat.com>, Daiki Ueno <dueno@redhat.com>
 */

#include "config.h"

#include "attrs.h"
#include "buffer.h"
#include "constants.h"
#define P11_DEBUG_FLAG P11_DEBUG_TOOL
#include "debug.h"
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

int
p11_kit_export_object (int argc,
		       char *argv[]);

#ifdef WITH_ASN1

typedef struct {
	p11_dict *defs;
	P11KitIter *iter;
} ExportData;

static void
export_data_uninit (ExportData *data)
{
	p11_dict_free (data->defs);
}

static void
prepend_leading_zero (CK_ATTRIBUTE *attr)
{
	if (*((unsigned char *)attr->pValue) & 0x80) {
		unsigned char *padded;

		return_if_fail (attr->ulValueLen < ULONG_MAX);
		padded = malloc (attr->ulValueLen + 1);
		return_if_fail (padded);
		memcpy (padded + 1, attr->pValue, attr->ulValueLen);
		*padded = 0x00;
		free (attr->pValue);
		attr->pValue = padded;
		attr->ulValueLen++;
	}
}

static unsigned char *
encode_pubkey_rsa (const ExportData *data,
		   CK_ATTRIBUTE *attrs,
		   size_t *len)
{
	asn1_node asn = NULL;
	CK_ATTRIBUTE *modulus, *public_exponent;
	unsigned char *der = NULL;
	int result;

	modulus = p11_attrs_find_valid (attrs, CKA_MODULUS);
	public_exponent = p11_attrs_find_valid (attrs, CKA_PUBLIC_EXPONENT);

	if (!modulus || !public_exponent) {
		p11_message (_("failed to retrieve attributes"));
		goto cleanup;
	}

	asn = p11_asn1_create (data->defs, "PKIX1.RSAPublicKey");
	if (!asn) {
		p11_debug ("unable to create RSAPublicKey");
		return NULL;
	}

	prepend_leading_zero (modulus);
	result = asn1_write_value (asn, "modulus", modulus->pValue, modulus->ulValueLen);
	if (result != ASN1_SUCCESS) {
		p11_debug ("unable to write modulus");
		goto cleanup;
	}

	prepend_leading_zero (public_exponent);
	result = asn1_write_value (asn, "publicExponent", public_exponent->pValue, public_exponent->ulValueLen);
	if (result != ASN1_SUCCESS) {
		p11_debug ("unable to write publicExponent");
		goto cleanup;
	}

	der = p11_asn1_encode (asn, len);
	if (!der) {
		p11_message ("unable to encode RSAPublicKey");
		goto cleanup;
	}

 cleanup:
	p11_asn1_free (asn);
	return der;
}

static unsigned char *
export_pubkey_rsa (const ExportData *data,
		   size_t *len)
{
	CK_ATTRIBUTE template[] = {
		{ CKA_MODULUS, },
		{ CKA_PUBLIC_EXPONENT, },
		{ CKA_INVALID },
	};
	CK_ATTRIBUTE *attrs = NULL;
	asn1_node asn = NULL;
	int result;
	unsigned char *spk = NULL, *der = NULL;
	const unsigned char null[] = { 0x05, 0x00 };
	size_t n_spk;

	attrs = p11_attrs_buildn (NULL, template, p11_attrs_count (template));
	if (!attrs) {
		p11_debug ("unable to build attributes");
		return NULL;
	}

	if (p11_kit_iter_load_attributes (data->iter,
					  attrs,
					  p11_attrs_count (attrs)) != CKR_OK) {
		p11_message (_("failed to retrieve attributes"));
		goto cleanup;
	}

	asn = p11_asn1_create (data->defs, "PKIX1.SubjectPublicKeyInfo");
	if (!asn) {
		p11_debug ("unable to create SubjectPublicKeyInfo");
		goto cleanup;
	}

	result = asn1_write_value (asn, "algorithm.algorithm",
				   P11_OID_PKIX1_RSA_STR, 1);
	if (result != ASN1_SUCCESS) {
		p11_debug ("unable to write algorithm OID");
		goto cleanup;
	}

	result = asn1_write_value (asn, "algorithm.parameters",
				   null, sizeof (null));
	if (result != ASN1_SUCCESS) {
		p11_debug ("unable to write algorithm parameters");
		goto cleanup;
	}

	spk = encode_pubkey_rsa (data, attrs, &n_spk);
	if (!spk) {
		p11_debug ("unable to encode RSA public key");
		goto cleanup;
	}

	result = asn1_write_value (asn, "subjectPublicKey", spk, n_spk * 8);
	if (result != ASN1_SUCCESS) {
		p11_debug ("unable to write subjectPublicKey for RSA");
		goto cleanup;
	}

	der = p11_asn1_encode (asn, len);

cleanup:
	free (spk);
	p11_asn1_free (asn);
	p11_attrs_free (attrs);
	return der;
}

static unsigned char *
export_pubkey_ec (const ExportData *data,
		  size_t *len)
{
	CK_ATTRIBUTE template[] = {
		{ CKA_EC_PARAMS, },
		{ CKA_EC_POINT, },
		{ CKA_INVALID },
	};
	CK_ATTRIBUTE *attrs = NULL;
	const CK_ATTRIBUTE *ec_params, *ec_point;
	asn1_node asn = NULL;
	int result;
	unsigned char *der = NULL;

	attrs = p11_attrs_buildn (NULL, template, p11_attrs_count (template));
	return_val_if_fail (attrs, false);

	if (p11_kit_iter_load_attributes (data->iter,
					  attrs,
					  p11_attrs_count (attrs)) != CKR_OK) {
		p11_message (_("failed to retrieve attributes"));
		goto cleanup;
	}

	ec_params = p11_attrs_find_valid (attrs, CKA_EC_PARAMS);
	ec_point = p11_attrs_find_valid (attrs, CKA_EC_POINT);

	if (!ec_params || !ec_point) {
		p11_message (_("failed to retrieve attributes"));
		goto cleanup;
	}

	asn = p11_asn1_create (data->defs, "PKIX1.SubjectPublicKeyInfo");
	if (!asn) {
		p11_debug ("unable to create SubjectPublicKeyInfo");
		goto cleanup;
	}

	result = asn1_write_value (asn, "algorithm.algorithm",
				   P11_OID_PKIX1_EC_STR, 1);
	if (result != ASN1_SUCCESS) {
		p11_debug ("unable to write algorithm OID");
		goto cleanup;
	}

	result = asn1_write_value (asn, "algorithm.parameters",
				   ec_params->pValue, ec_params->ulValueLen);
	if (result != ASN1_SUCCESS) {
		p11_debug ("unable to write algorithm parameters");
		goto cleanup;
	}

	/* Strip the leading 2 octets (DER header) for OCTET STRING */
	if (ec_point->ulValueLen < 2) {
		p11_message (_("corrupted value in attributes"));
		goto cleanup;
	}

	result = asn1_write_value (asn, "subjectPublicKey",
				   ((unsigned char *)ec_point->pValue) + 2,
				   (ec_point->ulValueLen - 2) * 8);
	if (result != ASN1_SUCCESS) {
		p11_debug ("unable to write value");
		goto cleanup;
	}

	der = p11_asn1_encode (asn, len);

cleanup:
	p11_asn1_free (asn);
	p11_attrs_free (attrs);
	return der;
}

static unsigned char *
export_pubkey_asn1 (P11KitIter *iter,
		    CK_KEY_TYPE type,
		    size_t *len)
{
	ExportData data;
	unsigned char *der = NULL;

	data.defs = p11_asn1_defs_load ();
	if (!data.defs)
		goto cleanup;
	data.iter = iter;

	switch (type) {
	case CKK_RSA:
		der = export_pubkey_rsa (&data, len);
		break;
	case CKK_EC:
		der = export_pubkey_ec (&data, len);
		break;
	default:
		p11_message (_("unsupported key type: %lu"), type);
		goto cleanup;
	}

cleanup:
	export_data_uninit (&data);
	return der;
}
#endif /* WITH_ASN1 */

static bool
export_pubkey (P11KitIter *iter,
	       p11_buffer *buf)
{
	CK_ATTRIBUTE template[] = {
		{ CKA_PUBLIC_KEY_INFO, },
		{ CKA_KEY_TYPE, },
	};
	CK_ATTRIBUTE *attrs = NULL, *attr;
	unsigned char *der = NULL;
	size_t n_der;
	bool ok = false;

	attrs = p11_attrs_buildn (NULL, template, 2);
	return_val_if_fail (attrs, false);

	if (p11_kit_iter_load_attributes (iter, attrs, p11_attrs_count (attrs)) != CKR_OK) {
		p11_message (_("failed to retrieve attributes"));
		goto cleanup;
	}

	attr = p11_attrs_find_valid (attrs, CKA_PUBLIC_KEY_INFO);
	if (attr) {
		der = attr->pValue;
		attr->pValue = NULL;
		n_der = attr->ulValueLen;
	} else {
#ifdef WITH_ASN1
		CK_KEY_TYPE type;

		if (!p11_attrs_find_ulong (attrs, CKA_KEY_TYPE, &type)) {
			p11_message (_("unable to determine key type"));
			goto cleanup;
		}

		der = export_pubkey_asn1 (iter, type, &n_der);
#else /* WITH_ASN1 */
		p11_message (_("ASN.1 support is not compiled in"));
		goto cleanup;
#endif /* !WITH_ASN1 */
	}

	if (!der || n_der == 0 ||
	    !p11_pem_write (der, n_der, "PUBLIC KEY", buf)) {
		p11_message (_("failed to export public key"));
		goto cleanup;
	}

	ok = true;

cleanup:
	p11_attrs_free (attrs);
	free (der);
	return ok;
}

static bool
export_certificate (P11KitIter *iter,
		    p11_buffer *buf)
{
	CK_CERTIFICATE_TYPE cert_type;
	CK_ATTRIBUTE template[] = {
		{ CKA_CERTIFICATE_TYPE, },
		{ CKA_VALUE, },
	};
	CK_ATTRIBUTE *attrs = NULL, *attr;
	bool ok = false;

	attrs = p11_attrs_buildn (NULL, template, 2);
	return_val_if_fail (attrs, false);

	if (p11_kit_iter_load_attributes (iter, attrs, p11_attrs_count (attrs)) != CKR_OK) {
		p11_message (_("failed to retrieve attributes"));
		goto cleanup;
	}

	if (!p11_attrs_find_ulong (attrs, CKA_CERTIFICATE_TYPE, &cert_type) ||
	    cert_type != CKC_X_509) {
		p11_message (_("unrecognized certificate type"));
		goto cleanup;
	}

	attr = p11_attrs_find_valid (attrs, CKA_VALUE);
	if (!attr) {
		p11_message (_("no valid certificate value"));
		goto cleanup;
	}

	if (!p11_pem_write (attr->pValue, attr->ulValueLen, "CERTIFICATE", buf)) {
		p11_message (_("failed to convert DER to PEM"));
		goto cleanup;
	}

	ok = true;

 cleanup:
	p11_attrs_free (attrs);
	return ok;
}

static int
export_object (p11_tool *tool)
{
	int ret = 1;
	CK_RV rv;
	P11KitIter *iter = NULL;
	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE attr = { CKA_CLASS, &klass, sizeof (klass) };
	p11_buffer buf;

	if (!p11_buffer_init (&buf, 0))
		return_val_if_reached (1);

	iter = p11_tool_begin_iter (tool, 0);
	if (iter == NULL) {
		p11_message (_("failed to initialize iterator"));
		return 1;
	}

	rv = p11_kit_iter_next (iter);
	if (rv != CKR_OK) {
		if (rv == CKR_CANCEL)
			p11_message (_("no matching object"));
		else
			p11_message (_("failed to find object: %s"),
				     p11_kit_strerror (rv));
		goto cleanup;
	}

	if (p11_kit_iter_get_attributes (iter, &attr, 1) != CKR_OK) {
		p11_message (_("failed to retrieve attribute of an object"));
		goto cleanup;
	}

	switch (klass) {
	case CKO_CERTIFICATE:
		if (!export_certificate (iter, &buf))
			goto cleanup;
		break;
	case CKO_PUBLIC_KEY:
		if (!export_pubkey (iter, &buf))
			goto cleanup;
		break;
	default:
		p11_message (_("unsupported object class"));
		goto cleanup;
	}

	if (fwrite (buf.data, 1, buf.len, stdout) != buf.len) {
		p11_message (_("failed to write PEM data to stdout"));
		goto cleanup;
	}

	ret = 0;

cleanup:
	p11_buffer_uninit (&buf);
	p11_tool_end_iter (tool, iter);

	return ret;
}

int
p11_kit_export_object (int argc,
		       char *argv[])
{
	int opt, ret = 2;
	bool login = false;
	p11_tool *tool = NULL;
	const char *provider = NULL;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
		opt_login = 'l',
		opt_provider = CHAR_MAX + 2,
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ "login", no_argument, NULL, opt_login },
		{ "provider", required_argument, NULL, opt_provider },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit export-object pkcs11:token" },
		{ opt_login, "login to the token" },
		{ opt_provider, "specify the module to use" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
			p11_kit_be_loud ();
			break;
		case opt_quiet:
			p11_kit_be_quiet ();
			break;
		case opt_help:
			p11_tool_usage (usages, options);
			return 0;
		case opt_login:
			login = true;
			break;
		case opt_provider:
			provider = optarg;
			break;
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

	tool = p11_tool_new ();
	if (!tool) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	if (p11_tool_set_uri (tool, *argv, P11_KIT_URI_FOR_OBJECT_ON_TOKEN) != P11_KIT_URI_OK) {
		p11_message (_("failed to parse URI"));
		goto cleanup;
	}

	if (!p11_tool_set_provider (tool, provider)) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	p11_tool_set_login (tool, login);

	ret = export_object (tool);

 cleanup:
	p11_tool_free (tool);

	return ret;
}
