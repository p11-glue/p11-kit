/*
 * Copyright (c) 2013, Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "attrs.h"
#include "debug.h"
#include "oid.h"
#include "dict.h"
#include "extract.h"
#include "library.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "x509.h"

#include <stdlib.h>
#include <string.h>

static p11_dict *
load_stapled_extensions (CK_FUNCTION_LIST_PTR module,
                         CK_SLOT_ID slot_id,
                         CK_ATTRIBUTE *id)
{
	CK_OBJECT_CLASS extension = CKO_X_CERTIFICATE_EXTENSION;
	CK_ATTRIBUTE *attrs;
	P11KitIter *iter;
	CK_RV rv = CKR_OK;
	p11_dict *stapled;

	CK_ATTRIBUTE match[] = {
		{ CKA_CLASS, &extension, sizeof (extension) },
		{ CKA_ID, id->pValue, id->ulValueLen },
	};

	CK_ATTRIBUTE template[] = {
		{ CKA_OBJECT_ID, },
		{ CKA_X_CRITICAL, },
		{ CKA_VALUE, },
	};

	stapled = p11_dict_new (p11_attr_hash,
	                        (p11_dict_equals)p11_attr_equal,
	                        NULL, p11_attrs_free);

	/* No ID to use, just short circuit */
	if (!id->pValue || !id->ulValueLen)
		return stapled;

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_add_filter (iter, match, 2);
	p11_kit_iter_begin_with (iter, module, slot_id, 0);

	while (rv == CKR_OK) {
		rv = p11_kit_iter_next (iter);
		if (rv == CKR_OK) {
			attrs = p11_attrs_buildn (NULL, template, 3);
			rv = p11_kit_iter_load_attributes (iter, attrs, 3);
			if (rv == CKR_OK || rv == CKR_ATTRIBUTE_TYPE_INVALID) {
				/* CKA_OBJECT_ID is the first attribute, use it as the key */
				if (!p11_dict_set (stapled, attrs, attrs))
					return_val_if_reached (NULL);
				rv = CKR_OK;
			} else {
				p11_attrs_free (attrs);
			}
		}
	}

	if (rv != CKR_OK && rv != CKR_CANCEL) {
		p11_message ("couldn't load stapled extensions for certificate: %s", p11_kit_strerror (rv));
		p11_dict_free (stapled);
		stapled = NULL;
	}

	p11_kit_iter_free (iter);
	return stapled;
}

static bool
extract_purposes (p11_extract_info *ex)
{
	CK_ATTRIBUTE oid = { CKA_OBJECT_ID,
	                     (void *)P11_OID_EXTENDED_KEY_USAGE,
	                     sizeof (P11_OID_EXTENDED_KEY_USAGE) };
	const unsigned char *ext = NULL;
	unsigned char *alloc = NULL;
	CK_ATTRIBUTE *value;
	CK_ATTRIBUTE *attrs;
	size_t ext_len;

	if (ex->stapled) {
		attrs = p11_dict_get (ex->stapled, &oid);
		if (attrs != NULL) {
			value = p11_attrs_find (attrs, CKA_VALUE);
			if (value) {
				ext = value->pValue;
				ext_len = value->ulValueLen;
			}
		}
	}

	if (ext == NULL && ex->cert_asn) {
		alloc = p11_x509_find_extension (ex->cert_asn, P11_OID_EXTENDED_KEY_USAGE,
		                                 ex->cert_der, ex->cert_len, &ext_len);
		ext = alloc;
	}

	/* No such extension, match anything */
	if (ext == NULL)
		return true;

	ex->purposes = p11_x509_parse_extended_key_usage (ex->asn1_defs, ext, ext_len);

	free (alloc);
	return ex->purposes != NULL;
}

static bool
extract_certificate (P11KitIter *iter,
                     p11_extract_info *ex)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	CK_ATTRIBUTE *attr;
	CK_ULONG type;

	/* Don't even bother with not X.509 certificates */
	if (!p11_attrs_find_ulong (ex->attrs, CKA_CERTIFICATE_TYPE, &type))
		type = (CK_ULONG)-1;
	if (type != CKC_X_509)
		return false;

	attr = p11_attrs_find_valid (ex->attrs, CKA_VALUE);
	if (!attr || !attr->pValue)
		return false;

	ex->cert_der = attr->pValue;
	ex->cert_len = attr->ulValueLen;
	ex->cert_asn = p11_asn1_decode (ex->asn1_defs, "PKIX1.Certificate",
	                                ex->cert_der, ex->cert_len, message);

	if (!ex->cert_asn) {
		p11_message ("couldn't parse certificate: %s", message);
		return false;
	}

	return true;
}

static bool
extract_info (P11KitIter *iter,
              p11_extract_info *ex)
{
	CK_ATTRIBUTE *attr;
	CK_RV rv;

	static CK_ATTRIBUTE attr_types[] = {
		{ CKA_ID, },
		{ CKA_CLASS, },
		{ CKA_CERTIFICATE_TYPE, },
		{ CKA_LABEL, },
		{ CKA_VALUE, },
		{ CKA_SUBJECT, },
		{ CKA_ISSUER, },
		{ CKA_TRUSTED, },
		{ CKA_CERTIFICATE_CATEGORY },
		{ CKA_X_DISTRUSTED },
		{ CKA_INVALID, },
	};

	ex->attrs = p11_attrs_dup (attr_types);
	rv = p11_kit_iter_load_attributes (iter, ex->attrs, p11_attrs_count (ex->attrs));

	/* The attributes couldn't be loaded */
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID && rv != CKR_ATTRIBUTE_SENSITIVE) {
		p11_message ("couldn't load attributes: %s", p11_kit_strerror (rv));
		return false;
	}

	attr = p11_attrs_find (ex->attrs, CKA_CLASS);

	/* No class attribute, very strange, just skip */
	if (!attr || !attr->pValue || attr->ulValueLen != sizeof (CK_OBJECT_CLASS))
		return false;

	ex->klass = *((CK_ULONG *)attr->pValue);

	/* If a certificate then  */
	if (ex->klass != CKO_CERTIFICATE) {
		p11_message ("skipping non-certificate object");
		return false;
	}

	if (!extract_certificate (iter, ex))
		return false;

	attr = p11_attrs_find (ex->attrs, CKA_ID);
	if (attr) {
		ex->stapled = load_stapled_extensions (p11_kit_iter_get_module (iter),
		                                       p11_kit_iter_get_slot (iter),
		                                       attr);
		if (!ex->stapled)
			return false;
	}

	if (!extract_purposes (ex))
		return false;

	return true;
}

static void
extract_clear (p11_extract_info *ex)
{
	ex->klass = (CK_ULONG)-1;

	p11_attrs_free (ex->attrs);
	ex->attrs = NULL;

	asn1_delete_structure (&ex->cert_asn);
	ex->cert_der = NULL;
	ex->cert_len = 0;

	p11_dict_free (ex->stapled);
	ex->stapled = NULL;

	p11_array_free (ex->purposes);
	ex->purposes = NULL;
}

CK_RV
p11_extract_info_load_filter (P11KitIter *iter,
                              CK_BBOOL *matches,
                              void *data)
{
	p11_extract_info *ex = data;
	int i;

	extract_clear (ex);

	/* Try to load the certificate and extensions */
	if (!extract_info (iter, ex)) {
		*matches = CK_FALSE;
		return CKR_OK;
	}

	/*
	 * Limit to certain purposes. Note that the lack of purposes noted
	 * on the certificate means they match any purpose. This is the
	 * behavior of the ExtendedKeyUsage extension.
	 */
	if (ex->limit_to_purposes && ex->purposes) {
		*matches = CK_FALSE;
		for (i = 0; i < ex->purposes->num; i++) {
			if (p11_dict_get (ex->limit_to_purposes, ex->purposes->elem[i])) {
				*matches = CK_TRUE;
				break;
			}
		}
	}

	return CKR_OK;
}

void
p11_extract_info_init (p11_extract_info *ex)
{
	memset (ex, 0, sizeof (p11_extract_info));
	ex->asn1_defs = p11_asn1_defs_load ();
	return_if_fail (ex->asn1_defs != NULL);
}

void
p11_extract_info_cleanup (p11_extract_info *ex)
{
	extract_clear (ex);

	p11_dict_free (ex->limit_to_purposes);
	ex->limit_to_purposes = NULL;

	p11_dict_free (ex->asn1_defs);
	ex->asn1_defs = NULL;
}

void
p11_extract_info_limit_purpose (p11_extract_info *ex,
                                const char *purpose)
{
	char *value;

	if (!ex->limit_to_purposes) {
		ex->limit_to_purposes = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, NULL);
		return_if_fail (ex->limit_to_purposes != NULL);
	}

	value = strdup (purpose);
	return_if_fail (value != NULL);

	if (!p11_dict_set (ex->limit_to_purposes, value, value))
		return_if_reached ();
}

static char *
extract_label (p11_extract_info *extract)
{
	CK_ATTRIBUTE *attr;

	/* Look for a label and just use that */
	attr = p11_attrs_find (extract->attrs, CKA_LABEL);
	if (attr && attr->pValue && attr->ulValueLen)
		return strndup (attr->pValue, attr->ulValueLen);

	/* For extracting certificates */
	if (extract->klass == CKO_CERTIFICATE)
		return strdup ("certificate");

	return strdup ("unknown");
}

#define FILENAME_CHARS \
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"

char *
p11_extract_info_filename (p11_extract_info *extract)
{
	char *label;
	int i;

	label = extract_label (extract);
	return_val_if_fail (label != NULL, NULL);

	for (i = 0; label[i] != '\0'; i++) {
		if (strchr (FILENAME_CHARS, label[i]) == NULL)
			label[i] = '_';
	}

	return label;
}
