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

#define P11_DEBUG_FLAG P11_DEBUG_TOOL

#include "attrs.h"
#include "debug.h"
#include "oid.h"
#include "dict.h"
#include "extract.h"
#include "message.h"
#include "path.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "x509.h"

#include <stdlib.h>
#include <string.h>

static bool
load_attached_extension (p11_dict *attached,
                         p11_dict *asn1_defs,
                         const unsigned char *der,
                         size_t len)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	node_asn *ext;
	char *oid;
	int length;
	int start;
	int end;
	int ret;

	ext = p11_asn1_decode (asn1_defs, "PKIX1.Extension", der, len, message);
	if (ext == NULL) {
		p11_message ("couldn't parse attached certificate extension: %s", message);
		return false;
	}

	ret = asn1_der_decoding_startEnd (ext, der, len, "extnID", &start, &end);
	return_val_if_fail (ret == ASN1_SUCCESS, false);

	/* Make sure it's a straightforward oid with certain assumptions */
	length = (end - start) + 1;
	if (!p11_oid_simple (der + start, length)) {
		p11_debug ("strange complex certificate extension object id");
		return false;
	}

	oid = memdup (der + start, length);
	return_val_if_fail (oid != NULL, false);

	if (!p11_dict_set (attached, oid, ext))
		return_val_if_reached (false);

	return true;
}

static p11_dict *
load_attached_extensions (p11_enumerate *ex,
                          CK_ATTRIBUTE *spki)
{
	CK_OBJECT_CLASS extension = CKO_X_CERTIFICATE_EXTENSION;
	CK_ATTRIBUTE *attrs;
	P11KitIter *iter;
	CK_RV rv = CKR_OK;
	p11_dict *attached;

	CK_ATTRIBUTE match[] = {
		{ CKA_CLASS, &extension, sizeof (extension) },
		{ CKA_PUBLIC_KEY_INFO, spki->pValue, spki->ulValueLen },
	};

	CK_ATTRIBUTE template[] = {
		{ CKA_VALUE, },
	};

	attached = p11_dict_new (p11_oid_hash, p11_oid_equal,
	                        free, p11_asn1_free);

	/* No ID to use, just short circuit */
	if (!spki->pValue || !spki->ulValueLen)
		return attached;

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_add_filter (iter, match, 2);
	p11_kit_iter_begin_with (iter, p11_kit_iter_get_module (ex->iter),
	                         0, p11_kit_iter_get_session (ex->iter));

	while (rv == CKR_OK) {
		rv = p11_kit_iter_next (iter);
		if (rv == CKR_OK) {
			attrs = p11_attrs_buildn (NULL, template, 1);
			rv = p11_kit_iter_load_attributes (iter, attrs, 1);
			if (rv == CKR_OK) {
				if (!load_attached_extension (attached, ex->asn1_defs,
				                              attrs[0].pValue,
				                              attrs[0].ulValueLen)) {
					rv = CKR_GENERAL_ERROR;
				}
			}
			p11_attrs_free (attrs);
		}
	}

	if (rv != CKR_OK && rv != CKR_CANCEL) {
		p11_message ("couldn't load attached extensions for certificate: %s", p11_kit_strerror (rv));
		p11_dict_free (attached);
		attached = NULL;
	}

	p11_kit_iter_free (iter);
	return attached;
}

static bool
extract_purposes (p11_enumerate *ex)
{
	node_asn *ext = NULL;
	unsigned char *value = NULL;
	size_t length;

	if (ex->attached) {
		ext = p11_dict_get (ex->attached, P11_OID_EXTENDED_KEY_USAGE);
		if (ext != NULL) {
			value = p11_asn1_read (ext, "extnValue", &length);
			return_val_if_fail (value != NULL, false);
		}
	}

	if (value == NULL && ex->cert_asn) {
		value = p11_x509_find_extension (ex->cert_asn, P11_OID_EXTENDED_KEY_USAGE,
		                                 ex->cert_der, ex->cert_len, &length);
	}

	/* No such extension, match anything */
	if (value == NULL)
		return true;

	ex->purposes = p11_x509_parse_extended_key_usage (ex->asn1_defs, value, length);

	free (value);
	return ex->purposes != NULL;
}

static bool
check_trust_flags (p11_enumerate *ex)
{
	CK_BBOOL trusted;
	CK_BBOOL distrusted;
	int flags = 0;

	/* If no extract trust flags, then just continue */
	if (!(ex->flags & (P11_ENUMERATE_ANCHORS | P11_ENUMERATE_BLACKLIST)))
		return true;

	/* Is this a blacklisted directly? */
	if (p11_attrs_find_bool (ex->attrs, CKA_X_DISTRUSTED, &distrusted) && distrusted)
		flags = P11_ENUMERATE_BLACKLIST;

	/* Is it blacklisted elsewhere? then prevent it from being an anchor */
	else if (p11_dict_get (ex->blacklist_public_key, ex->attrs) ||
	         p11_dict_get (ex->blacklist_issuer_serial, ex->attrs))
		flags = 0;

	/* Otherwise it might be an anchor? */
	else if (p11_attrs_find_bool (ex->attrs, CKA_TRUSTED, &trusted) && trusted)
		flags = P11_ENUMERATE_ANCHORS;

	/* Any of the flags can match */
	if (flags & ex->flags)
		return true;

	return false;
}

static bool
extract_certificate (p11_enumerate *ex)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	CK_ATTRIBUTE *attr;

	CK_ULONG type;

	/* Don't even bother with not X.509 certificates */
	if (!p11_attrs_find_ulong (ex->attrs, CKA_CERTIFICATE_TYPE, &type))
		type = (CK_ULONG)-1;
	if (type != CKC_X_509) {
		p11_debug ("skipping non X.509 certificate");
		return false;
	}

	attr = p11_attrs_find_valid (ex->attrs, CKA_VALUE);
	if (!attr || !attr->pValue) {
		p11_debug ("skipping certificate without a value");
		return false;
	}

	/*
	 * If collapsing and have already seen this certificate, and shouldn't
	 * process it even again during this extract procedure.
	 */
	if (ex->flags & P11_ENUMERATE_COLLAPSE) {
		if (!ex->already_seen) {
			ex->already_seen = p11_dict_new (p11_attr_hash, p11_attr_equal,
			                                 p11_attrs_free, NULL);
			return_val_if_fail (ex->already_seen != NULL, true);
		}

		if (p11_dict_get (ex->already_seen, attr))
			return false;
	}

	if (!check_trust_flags (ex)) {
		p11_debug ("skipping certificate that doesn't match trust flags");
		return false;
	}

	if (ex->already_seen) {
		if (!p11_dict_set (ex->already_seen,
		                   p11_attrs_build (NULL, attr, NULL), "x"))
			return_val_if_reached (true);
	}

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
extract_info (p11_enumerate *ex)
{
	CK_ATTRIBUTE *attr;
	CK_RV rv;

	static const CK_ATTRIBUTE attr_types[] = {
		{ CKA_ID, },
		{ CKA_CLASS, },
		{ CKA_CERTIFICATE_TYPE, },
		{ CKA_LABEL, },
		{ CKA_VALUE, },
		{ CKA_SUBJECT, },
		{ CKA_ISSUER, },
		{ CKA_SERIAL_NUMBER, },
		{ CKA_TRUSTED, },
		{ CKA_CERTIFICATE_CATEGORY },
		{ CKA_X_DISTRUSTED },
		{ CKA_PUBLIC_KEY_INFO },
		{ CKA_INVALID, },
	};

	ex->attrs = p11_attrs_dup (attr_types);
	rv = p11_kit_iter_load_attributes (ex->iter, ex->attrs, p11_attrs_count (ex->attrs));

	/* The attributes couldn't be loaded */
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID && rv != CKR_ATTRIBUTE_SENSITIVE) {
		p11_message ("couldn't load attributes: %s", p11_kit_strerror (rv));
		return false;
	}

	/* No class attribute, very strange, just skip */
	if (!p11_attrs_find_ulong (ex->attrs, CKA_CLASS, &ex->klass))
		return false;

	/* If a certificate then  */
	if (ex->klass != CKO_CERTIFICATE) {
		p11_message ("skipping non-certificate object");
		return false;
	}

	if (!extract_certificate (ex))
		return false;

	attr = p11_attrs_find_valid (ex->attrs, CKA_PUBLIC_KEY_INFO);
	if (attr) {
		ex->attached = load_attached_extensions (ex, attr);
		if (!ex->attached)
			return false;
	}

	if (!extract_purposes (ex))
		return false;

	return true;
}

static void
extract_clear (p11_enumerate *ex)
{
	ex->klass = (CK_ULONG)-1;

	p11_attrs_free (ex->attrs);
	ex->attrs = NULL;

	asn1_delete_structure (&ex->cert_asn);
	ex->cert_der = NULL;
	ex->cert_len = 0;

	p11_dict_free (ex->attached);
	ex->attached = NULL;

	p11_array_free (ex->purposes);
	ex->purposes = NULL;
}

static CK_RV
on_iterate_load_filter (p11_kit_iter *iter,
                        CK_BBOOL *matches,
                        void *data)
{
	p11_enumerate *ex = data;
	int i;

	extract_clear (ex);

	/* Try to load the certificate and extensions */
	if (!extract_info (ex)) {
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

/*
 * Various skip lookup tables, used for blacklists and collapsing
 * duplicate entries.
 *
 * The dict hash/lookup callbacks are special cased
 * so we can just pass in full attribute lists for lookup and only match
 * the attributes we're interested in.
 *
 * Note that both p11_attr_hash and p11_attr_equal are NULL safe.
 */

static bool
public_key_equal (const void *one,
                  const void *two)
{
	return p11_attr_equal (p11_attrs_find_valid ((CK_ATTRIBUTE *)one, CKA_PUBLIC_KEY_INFO),
	                       p11_attrs_find_valid ((CK_ATTRIBUTE *)two, CKA_PUBLIC_KEY_INFO));
}

static unsigned int
public_key_hash (const void *data)
{
	return p11_attr_hash (p11_attrs_find_valid ((CK_ATTRIBUTE *)data, CKA_PUBLIC_KEY_INFO));
}

static bool
issuer_serial_equal (const void *one,
                     const void *two)
{
	return p11_attr_equal (p11_attrs_find_valid ((CK_ATTRIBUTE *)one, CKA_ISSUER),
	                       p11_attrs_find_valid ((CK_ATTRIBUTE *)two, CKA_ISSUER)) &&
	       p11_attr_equal (p11_attrs_find_valid ((CK_ATTRIBUTE *)one, CKA_SERIAL_NUMBER),
	                       p11_attrs_find_valid ((CK_ATTRIBUTE *)two, CKA_SERIAL_NUMBER));
}

static unsigned int
issuer_serial_hash (const void *data)
{
	return p11_attr_hash (p11_attrs_find_valid ((CK_ATTRIBUTE *)data, CKA_ISSUER)) ^
	       p11_attr_hash (p11_attrs_find_valid ((CK_ATTRIBUTE *)data, CKA_SERIAL_NUMBER));
}

static bool
blacklist_load (p11_enumerate *ex)
{
	p11_kit_iter *iter;
	CK_BBOOL distrusted = CK_TRUE;
	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *key;
	CK_ATTRIBUTE *serial;
	CK_ATTRIBUTE *issuer;
	CK_ATTRIBUTE *public_key;

	CK_ATTRIBUTE match[] = {
		{ CKA_X_DISTRUSTED, &distrusted, sizeof (distrusted) },
	};

	CK_ATTRIBUTE template[] = {
		{ CKA_SERIAL_NUMBER, },
		{ CKA_PUBLIC_KEY_INFO, },
		{ CKA_ISSUER, },
	};

	iter = p11_kit_iter_new (ex->uri, 0);
	p11_kit_iter_add_filter (iter, match, 1);
	p11_kit_iter_begin (iter, ex->modules);

	attrs = p11_attrs_buildn (NULL, template, 3);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {

		/*
		 * Fail "safe" in that first failure doesn't cause ignoring
		 * the remainder of the blacklist.
		 */
		rv = p11_kit_iter_load_attributes (iter, attrs, 3);
		if (rv != CKR_OK) {
			p11_message ("couldn't load blacklist: %s", p11_kit_strerror (rv));
			continue;
		}

		/* A blacklisted item with an issuer and serial number */
		issuer = p11_attrs_find_valid (attrs, CKA_ISSUER);
		serial = p11_attrs_find_valid (attrs, CKA_SERIAL_NUMBER);
		if (issuer != NULL && serial != NULL) {
			key = p11_attrs_build (NULL, issuer, serial, NULL);
			if (!key || !p11_dict_set (ex->blacklist_issuer_serial, key, "x"))
				return_val_if_reached (false);
		}

		/* A blacklisted item with a public key */
		public_key = p11_attrs_find_valid (attrs, CKA_PUBLIC_KEY_INFO);
		if (public_key != NULL) {
			key = p11_attrs_build (NULL, public_key, NULL);
			if (!public_key || !p11_dict_set (ex->blacklist_public_key, key, "x"))
				return_val_if_reached (false);
		}
	}

	p11_attrs_free (attrs);
	p11_kit_iter_free (iter);

	if (rv == CKR_CANCEL)
		return true;

	p11_message ("couldn't load blacklist: %s", p11_kit_strerror (rv));
	return false;
}

void
p11_enumerate_init (p11_enumerate *ex)
{
	memset (ex, 0, sizeof (p11_enumerate));
	ex->asn1_defs = p11_asn1_defs_load ();
	return_if_fail (ex->asn1_defs != NULL);

	ex->iter = p11_kit_iter_new (NULL, 0);
	return_if_fail (ex->iter != NULL);

	ex->blacklist_public_key = p11_dict_new (public_key_hash, public_key_equal,
	                                         p11_attrs_free, NULL);
	return_if_fail (ex->blacklist_public_key);

	ex->blacklist_issuer_serial = p11_dict_new (issuer_serial_hash, issuer_serial_equal,
	                                            p11_attrs_free, NULL);
	return_if_fail (ex->blacklist_issuer_serial);

	p11_kit_iter_add_callback (ex->iter, on_iterate_load_filter, ex, NULL);
}

void
p11_enumerate_cleanup (p11_enumerate *ex)
{
	extract_clear (ex);

	p11_dict_free (ex->limit_to_purposes);
	ex->limit_to_purposes = NULL;

	p11_dict_free (ex->already_seen);
	ex->already_seen = NULL;
	p11_dict_free (ex->blacklist_public_key);
	ex->blacklist_public_key = NULL;
	p11_dict_free (ex->blacklist_issuer_serial);
	ex->blacklist_issuer_serial = NULL;

	p11_dict_free (ex->asn1_defs);
	ex->asn1_defs = NULL;

	p11_kit_iter_free (ex->iter);
	ex->iter = NULL;

	if (ex->modules) {
		p11_kit_modules_finalize_and_release (ex->modules);
		ex->modules = NULL;
	}

	if (ex->uri) {
		p11_kit_uri_free (ex->uri);
		ex->uri = NULL;
	}
}

bool
p11_enumerate_opt_filter (p11_enumerate *ex,
                          const char *option)
{
	CK_ATTRIBUTE *attrs;
	int ret;

	CK_OBJECT_CLASS vcertificate = CKO_CERTIFICATE;
	CK_ULONG vauthority = 2;
	CK_CERTIFICATE_TYPE vx509 = CKC_X_509;

	CK_ATTRIBUTE certificate = { CKA_CLASS, &vcertificate, sizeof (vcertificate) };
	CK_ATTRIBUTE authority = { CKA_CERTIFICATE_CATEGORY, &vauthority, sizeof (vauthority) };
	CK_ATTRIBUTE x509= { CKA_CERTIFICATE_TYPE, &vx509, sizeof (vx509) };

	if (strncmp (option, "pkcs11:", 7) == 0) {
		if (ex->uri != NULL) {
			p11_message ("a PKCS#11 URI has already been specified");
			return false;
		}

		ex->uri = p11_kit_uri_new ();
		ret = p11_kit_uri_parse (option, P11_KIT_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE, ex->uri);
		if (ret != P11_KIT_URI_OK) {
			p11_message ("couldn't parse pkcs11 uri filter: %s", option);
			return false;
		}

		if (p11_kit_uri_any_unrecognized (ex->uri))
			p11_message ("uri contained unrecognized components, nothing will be extracted");

		p11_kit_iter_set_uri (ex->iter, ex->uri);
		ex->num_filters++;
		return true;
	}

	if (strcmp (option, "ca-anchors") == 0) {
		attrs = p11_attrs_build (NULL, &certificate, &authority, &x509, NULL);
		ex->flags |= P11_ENUMERATE_ANCHORS | P11_ENUMERATE_COLLAPSE;

	} else if (strcmp (option, "trust-policy") == 0) {
		attrs = p11_attrs_build (NULL, &certificate, &x509, NULL);
		ex->flags |= P11_ENUMERATE_ANCHORS | P11_ENUMERATE_BLACKLIST | P11_ENUMERATE_COLLAPSE;

	} else if (strcmp (option, "blacklist") == 0) {
		attrs = p11_attrs_build (NULL, &certificate, &x509, NULL);
		ex->flags |= P11_ENUMERATE_BLACKLIST | P11_ENUMERATE_COLLAPSE;

	} else if (strcmp (option, "certificates") == 0) {
		attrs = p11_attrs_build (NULL, &certificate, &x509, NULL);
		ex->flags |= P11_ENUMERATE_COLLAPSE;

	} else {
		p11_message ("unsupported or unrecognized filter: %s", option);
		return false;
	}

	p11_kit_iter_add_filter (ex->iter, attrs, p11_attrs_count (attrs));
	ex->num_filters++;
	return true;
}

static int
is_valid_oid_rough (const char *string)
{
	size_t len;

	len = strlen (string);

	/* Rough check if a valid OID */
	return (strspn (string, "0123456789.") == len &&
	        !strstr (string, "..") && string[0] != '\0' && string[0] != '.' &&
	        string[len - 1] != '.');
}

bool
p11_enumerate_opt_purpose (p11_enumerate *ex,
                           const char *option)
{
	const char *oid;
	char *value;

	if (strcmp (option, "server-auth") == 0) {
		oid = P11_OID_SERVER_AUTH_STR;
	} else if (strcmp (option, "client-auth") == 0) {
		oid = P11_OID_CLIENT_AUTH_STR;
	} else if (strcmp (option, "email-protection") == 0 || strcmp (option, "email") == 0) {
		oid = P11_OID_EMAIL_PROTECTION_STR;
	} else if (strcmp (option, "code-signing") == 0) {
		oid = P11_OID_CODE_SIGNING_STR;
	} else if (strcmp (option, "ipsec-end-system") == 0) {
		oid = P11_OID_IPSEC_END_SYSTEM_STR;
	} else if (strcmp (option, "ipsec-tunnel") == 0) {
		oid = P11_OID_IPSEC_TUNNEL_STR;
	} else if (strcmp (option, "ipsec-user") == 0) {
		oid = P11_OID_IPSEC_USER_STR;
	} else if (strcmp (option, "time-stamping") == 0) {
		oid = P11_OID_TIME_STAMPING_STR;
	} else if (is_valid_oid_rough (option)) {
		oid = option;
	} else {
		p11_message ("unsupported or unregonized purpose: %s", option);
		return false;
	}

	if (!ex->limit_to_purposes) {
		ex->limit_to_purposes = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, NULL);
		return_val_if_fail (ex->limit_to_purposes != NULL, false);
	}

	value = strdup (oid);
	return_val_if_fail (value != NULL, false);
	if (!p11_dict_set (ex->limit_to_purposes, value, value))
		return_val_if_reached (false);

	return true;
}

bool
p11_enumerate_ready (p11_enumerate *ex,
                     const char *def_filter)
{
	if (def_filter && ex->num_filters == 0) {
		if (!p11_enumerate_opt_filter (ex, def_filter))
			return_val_if_reached (false);
	}

	/*
	 * We only "believe" the CKA_TRUSTED and CKA_X_DISTRUSTED attributes
	 * we get from modules explicitly marked as containing trust-policy.
	 */
	if (!ex->modules)
		ex->modules = p11_kit_modules_load_and_initialize (P11_KIT_MODULE_TRUSTED);
	if (!ex->modules)
		return false;
	if (ex->modules[0] == NULL)
		p11_message ("no modules containing trust policy are registered");

	/*
	 * If loading anchors, then the caller expects that the blacklist is
	 * "applied" and any anchors on the blacklist are taken out. This is
	 * for compatibility with software that does not support blacklists.
	 */
	if (ex->flags & P11_ENUMERATE_ANCHORS) {
		if (!blacklist_load (ex))
			return false;
	}

	p11_kit_iter_begin (ex->iter, ex->modules);
	return true;
}

static char *
extract_label (p11_enumerate *ex)
{
	CK_ATTRIBUTE *attr;

	/* Look for a label and just use that */
	attr = p11_attrs_find_valid (ex->attrs, CKA_LABEL);
	if (attr && attr->pValue && attr->ulValueLen)
		return strndup (attr->pValue, attr->ulValueLen);

	/* For extracting certificates */
	if (ex->klass == CKO_CERTIFICATE)
		return strdup ("certificate");

	return strdup ("unknown");
}

char *
p11_enumerate_filename (p11_enumerate *ex)
{
	char *label;

	label = extract_label (ex);
	return_val_if_fail (label != NULL, NULL);

	p11_path_canon (label);
	return label;
}

char *
p11_enumerate_comment (p11_enumerate *ex,
                       bool first)
{
	char *comment;
	char *label;

	if (!(ex->flags & P11_EXTRACT_COMMENT))
		return NULL;

	label = extract_label (ex);
	if (!asprintf (&comment, "%s# %s\n",
	               first ? "" : "\n",
	               label ? label : ""))
		return_val_if_reached (NULL);

	free (label);
	return comment;
}
