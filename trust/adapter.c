/*
 * Copyright (C) 2012 Red Hat Inc.
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

#include "adapter.h"
#include "attrs.h"
#include "checksum.h"
#include "dict.h"
#define P11_DEBUG_FLAG P11_DEBUG_TRUST
#include "debug.h"
#include "library.h"
#include "oid.h"
#include "parser.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "x509.h"

#include <stdlib.h>
#include <string.h>

static CK_ATTRIBUTE *
build_trust_object_ku (p11_parser *parser,
                        p11_array *parsing,
                        CK_ATTRIBUTE *object,
                        CK_TRUST present)
{
	unsigned char *data = NULL;
	unsigned int ku = 0;
	p11_dict *defs;
	size_t length;
	CK_TRUST defawlt;
	CK_ULONG i;

	struct {
		CK_ATTRIBUTE_TYPE type;
		unsigned int ku;
	} ku_attribute_map[] = {
		{ CKA_TRUST_DIGITAL_SIGNATURE, P11_KU_DIGITAL_SIGNATURE },
		{ CKA_TRUST_NON_REPUDIATION, P11_KU_NON_REPUDIATION },
		{ CKA_TRUST_KEY_ENCIPHERMENT, P11_KU_KEY_ENCIPHERMENT },
		{ CKA_TRUST_DATA_ENCIPHERMENT, P11_KU_DATA_ENCIPHERMENT },
		{ CKA_TRUST_KEY_AGREEMENT, P11_KU_KEY_AGREEMENT },
		{ CKA_TRUST_KEY_CERT_SIGN, P11_KU_KEY_CERT_SIGN },
		{ CKA_TRUST_CRL_SIGN, P11_KU_CRL_SIGN },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE attrs[sizeof (ku_attribute_map)];

	defawlt = present;

	/* If blacklisted, don't even bother looking at extensions */
	if (present != CKT_NSS_NOT_TRUSTED)
		data = p11_parsing_get_extension (parser, parsing, P11_OID_KEY_USAGE, &length);

	if (data) {
		/*
		 * If the certificate extension was missing, then *all* key
		 * usages are to be set. If the extension was invalid, then
		 * fail safe to none of the key usages.
		 */
		defawlt = CKT_NSS_TRUST_UNKNOWN;

		defs = p11_parser_get_asn1_defs (parser);
		if (!p11_x509_parse_key_usage (defs, data, length, &ku))
			p11_message ("invalid key usage certificate extension");
		free (data);
	}

	for (i = 0; ku_attribute_map[i].type != CKA_INVALID; i++) {
		attrs[i].type = ku_attribute_map[i].type;
		if (data && (ku & ku_attribute_map[i].ku) == ku_attribute_map[i].ku) {
			attrs[i].pValue = &present;
			attrs[i].ulValueLen = sizeof (present);
		} else {
			attrs[i].pValue = &defawlt;
			attrs[i].ulValueLen = sizeof (defawlt);
		}
	}

	return p11_attrs_buildn (object, attrs, i);
}

static bool
strv_to_dict (const char **array,
              p11_dict **dict)
{
	int i;

	if (!array) {
		*dict = NULL;
		return true;
	}

	*dict = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);
	return_val_if_fail (*dict != NULL, false);

	for (i = 0; array[i] != NULL; i++) {
		if (!p11_dict_set (*dict, (void *)array[i], (void *)array[i]))
			return_val_if_reached (false);
	}

	return true;
}

static CK_ATTRIBUTE *
build_trust_object_eku (p11_parser *parser,
                        p11_array *parsing,
                        CK_ATTRIBUTE *object,
                        CK_TRUST allow,
                        const char **purposes,
                        const char **rejects)
{
	p11_dict *dict_purp;
	p11_dict *dict_rej;
	CK_TRUST neutral;
	CK_TRUST disallow;
	CK_ULONG i;

	struct {
		CK_ATTRIBUTE_TYPE type;
		const char *oid;
	} eku_attribute_map[] = {
		{ CKA_TRUST_SERVER_AUTH, P11_OID_SERVER_AUTH_STR },
		{ CKA_TRUST_CLIENT_AUTH, P11_OID_CLIENT_AUTH_STR },
		{ CKA_TRUST_CODE_SIGNING, P11_OID_CODE_SIGNING_STR },
		{ CKA_TRUST_EMAIL_PROTECTION, P11_OID_EMAIL_PROTECTION_STR },
		{ CKA_TRUST_IPSEC_END_SYSTEM, P11_OID_IPSEC_END_SYSTEM_STR },
		{ CKA_TRUST_IPSEC_TUNNEL, P11_OID_IPSEC_TUNNEL_STR },
		{ CKA_TRUST_IPSEC_USER, P11_OID_IPSEC_USER_STR },
		{ CKA_TRUST_TIME_STAMPING, P11_OID_TIME_STAMPING_STR },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE attrs[sizeof (eku_attribute_map)];

	if (!strv_to_dict (purposes, &dict_purp) ||
	    !strv_to_dict (rejects, &dict_rej))
		return_val_if_reached (NULL);

	/* The neutral value is set if an purpose is not present */
	if (allow == CKT_NSS_NOT_TRUSTED)
		neutral = CKT_NSS_NOT_TRUSTED;

	/* If anything explicitly set, then neutral is unknown */
	else if (purposes || rejects)
		neutral = CKT_NSS_TRUST_UNKNOWN;

	/* Otherwise neutral will allow any purpose */
	else
		neutral = allow;

	/* The value set if a purpose is explictly rejected */
	disallow = CKT_NSS_NOT_TRUSTED;

	for (i = 0; eku_attribute_map[i].type != CKA_INVALID; i++) {
		attrs[i].type = eku_attribute_map[i].type;
		if (dict_rej && p11_dict_get (dict_rej, eku_attribute_map[i].oid)) {
			attrs[i].pValue = &disallow;
			attrs[i].ulValueLen = sizeof (disallow);
		} else if (dict_purp && p11_dict_get (dict_purp, eku_attribute_map[i].oid)) {
			attrs[i].pValue = &allow;
			attrs[i].ulValueLen = sizeof (allow);
		} else {
			attrs[i].pValue = &neutral;
			attrs[i].ulValueLen = sizeof (neutral);
		}
	}

	p11_dict_free (dict_purp);
	p11_dict_free (dict_rej);

	return p11_attrs_buildn (object, attrs, i);
}

static void
build_nss_trust_object (p11_parser *parser,
                        p11_array *parsing,
                        CK_ATTRIBUTE *cert,
                        CK_BBOOL trust,
                        CK_BBOOL distrust,
                        CK_BBOOL authority,
                        const char **purposes,
                        const char **rejects)
{
	CK_ATTRIBUTE *object = NULL;
	CK_TRUST allow;

	CK_OBJECT_CLASS vclass = CKO_NSS_TRUST;
	CK_BYTE vsha1_hash[P11_CHECKSUM_SHA1_LENGTH];
	CK_BYTE vmd5_hash[P11_CHECKSUM_MD5_LENGTH];
	CK_BBOOL vfalse = CK_FALSE;
	CK_BBOOL vtrue = CK_TRUE;

	CK_ATTRIBUTE klass = { CKA_CLASS, &vclass, sizeof (vclass) };
	CK_ATTRIBUTE token = { CKA_TOKEN, &vtrue, sizeof (vtrue) };
	CK_ATTRIBUTE private = { CKA_PRIVATE, &vfalse, sizeof (vfalse) };
	CK_ATTRIBUTE modifiable = { CKA_MODIFIABLE, &vfalse, sizeof (vfalse) };
	CK_ATTRIBUTE invalid = { CKA_INVALID, };

	CK_ATTRIBUTE md5_hash = { CKA_CERT_MD5_HASH, vmd5_hash, sizeof (vmd5_hash) };
	CK_ATTRIBUTE sha1_hash = { CKA_CERT_SHA1_HASH, vsha1_hash, sizeof (vsha1_hash) };

	CK_ATTRIBUTE step_up_approved = { CKA_TRUST_STEP_UP_APPROVED, &vfalse, sizeof (vfalse) };

	CK_ATTRIBUTE_PTR label;
	CK_ATTRIBUTE_PTR id;
	CK_ATTRIBUTE_PTR der;
	CK_ATTRIBUTE_PTR subject;
	CK_ATTRIBUTE_PTR issuer;
	CK_ATTRIBUTE_PTR serial_number;

	/* Setup the hashes of the DER certificate value */
	der = p11_attrs_find (cert, CKA_VALUE);
	return_if_fail (der != NULL);
	p11_checksum_md5 (vmd5_hash, der->pValue, der->ulValueLen, NULL);
	p11_checksum_sha1 (vsha1_hash, der->pValue, der->ulValueLen, NULL);

	/* Copy all of the following attributes from certificate */
	id = p11_attrs_find (cert, CKA_ID);
	return_if_fail (id != NULL);
	subject = p11_attrs_find (cert, CKA_SUBJECT);
	return_if_fail (subject != NULL);
	issuer = p11_attrs_find (cert, CKA_ISSUER);
	return_if_fail (issuer != NULL);
	serial_number = p11_attrs_find (cert, CKA_SERIAL_NUMBER);
	return_if_fail (serial_number != NULL);

	/* Try to use the same label */
	label = p11_attrs_find (cert, CKA_LABEL);
	if (label == NULL)
		label = &invalid;

	object = p11_attrs_build (NULL, &klass, &token, &private, &modifiable, id, label,
	                          subject, issuer, serial_number, &md5_hash, &sha1_hash,
	                          &step_up_approved, NULL);
	return_if_fail (object != NULL);

	/* Calculate the default allow trust */
	if (distrust)
		allow = CKT_NSS_NOT_TRUSTED;
	else if (trust && authority)
		allow = CKT_NSS_TRUSTED_DELEGATOR;
	else if (trust)
		allow = CKT_NSS_TRUSTED;
	else
		allow = CKT_NSS_TRUST_UNKNOWN;

	object = build_trust_object_ku (parser, parsing, object, allow);
	return_if_fail (object != NULL);

	object = build_trust_object_eku (parser, parsing, object, allow, purposes, rejects);
	return_if_fail (object != NULL);

	if (!p11_array_push (parsing, object))
		return_if_reached ();
}

static void
build_assertions (p11_parser *parser,
                  p11_array *parsing,
                  CK_ATTRIBUTE *cert,
                  CK_X_ASSERTION_TYPE type,
                  const char **oids)
{
	CK_OBJECT_CLASS assertion = CKO_X_TRUST_ASSERTION;
	CK_BBOOL vtrue = CK_TRUE;
	CK_BBOOL vfalse = CK_FALSE;

	CK_ATTRIBUTE klass = { CKA_CLASS, &assertion, sizeof (assertion) };
	CK_ATTRIBUTE token = { CKA_TOKEN, &vtrue, sizeof (vtrue) };
	CK_ATTRIBUTE private = { CKA_PRIVATE, &vfalse, sizeof (vfalse) };
	CK_ATTRIBUTE modifiable = { CKA_MODIFIABLE, &vfalse, sizeof (vfalse) };
	CK_ATTRIBUTE assertion_type = { CKA_X_ASSERTION_TYPE, &type, sizeof (type) };
	CK_ATTRIBUTE purpose = { CKA_X_PURPOSE, };
	CK_ATTRIBUTE invalid = { CKA_INVALID, };

	CK_ATTRIBUTE *issuer;
	CK_ATTRIBUTE *serial;
	CK_ATTRIBUTE *value;
	CK_ATTRIBUTE *label;
	CK_ATTRIBUTE *id;
	CK_ATTRIBUTE *object;
	int i;

	label = p11_attrs_find (cert, CKA_LABEL);
	if (label == NULL)
		label = &invalid;

	id = p11_attrs_find (cert, CKA_ID);
	issuer = p11_attrs_find (cert, CKA_ISSUER);
	serial = p11_attrs_find (cert, CKA_SERIAL_NUMBER);
	value = p11_attrs_find (cert, CKA_VALUE);

	return_if_fail (id != NULL && issuer != NULL && serial != NULL && value != NULL);

	for (i = 0; oids[i] != NULL; i++) {
		purpose.pValue = (void *)oids[i];
		purpose.ulValueLen = strlen (oids[i]);

		object = p11_attrs_build (NULL, &klass, &token, &private, &modifiable,
		                          id, label, &assertion_type, &purpose,
		                          issuer, serial, value, NULL);
		return_if_fail (object != NULL);

		if (!p11_array_push (parsing, object))
			return_if_reached ();
	}
}

static void
build_trust_assertions (p11_parser *parser,
                        p11_array *parsing,
                        CK_ATTRIBUTE *cert,
                        CK_BBOOL trust,
                        CK_BBOOL distrust,
                        CK_BBOOL authority,
                        const char **purposes,
                        const char **rejects)
{
	const char *all_purposes[] = {
		P11_OID_SERVER_AUTH_STR,
		P11_OID_CLIENT_AUTH_STR,
		P11_OID_CODE_SIGNING_STR,
		P11_OID_EMAIL_PROTECTION_STR,
		P11_OID_IPSEC_END_SYSTEM_STR,
		P11_OID_IPSEC_TUNNEL_STR,
		P11_OID_IPSEC_USER_STR,
		P11_OID_TIME_STAMPING_STR,
		NULL,
	};

	/* Build assertions for anything that's explicitly rejected */
	if (rejects) {
		build_assertions (parser, parsing, cert,
		                  CKT_X_DISTRUSTED_CERTIFICATE, rejects);
	}

	if (distrust) {
		/*
		 * Trust assertions are defficient in that they don't blacklist a certificate
		 * for any purposes. So we just have to go wild and write out a bunch of
		 * assertions for all our known purposes.
		 */
		build_assertions (parser, parsing, cert,
		                  CKT_X_DISTRUSTED_CERTIFICATE, all_purposes);
	}

	/*
	 * TODO: Build pinned certificate assertions. That is, trusted
	 * certificates where not an authority.
	 */

	if (trust && authority) {
		if (purposes) {
			/* If purposes explicitly set, then anchor for those purposes */
			build_assertions (parser, parsing, cert,
			                  CKT_X_ANCHORED_CERTIFICATE, purposes);
		} else {
			/* If purposes not-explicitly set, then anchor for all known */
			build_assertions (parser, parsing, cert,
			                  CKT_X_ANCHORED_CERTIFICATE, all_purposes);
		}
	}
}

void
p11_adapter_build_objects (p11_parser *parser,
                           p11_array *parsing)
{
	CK_ATTRIBUTE *cert;
	CK_ULONG category;
	CK_BBOOL trust = CK_FALSE;
	CK_BBOOL distrust = CK_FALSE;
	CK_BBOOL authority = CK_FALSE;
	p11_array *purposes = NULL;
	p11_array *rejects = NULL;
	const char **purposev;
	const char **rejectv;
	unsigned char *data;
	p11_dict *defs;
	size_t length;

	cert = p11_parsing_get_certificate (parser, parsing);
	return_if_fail (cert != NULL);

	/*
	 * We look up all this information in advance, since it's used
	 * by the various adapter objects, and we don't have to parse
	 * it multiple times.
	 */

	if (!p11_attrs_find_bool (cert, CKA_TRUSTED, &trust))
		trust = CK_FALSE;
	if (!p11_attrs_find_bool (cert, CKA_X_DISTRUSTED, &distrust))
		distrust = CK_FALSE;
	if (p11_attrs_find_ulong (cert, CKA_CERTIFICATE_CATEGORY, &category) && category == 2)
		authority = CK_TRUE;

	if (!distrust) {
		data = p11_parsing_get_extension (parser, parsing, P11_OID_EXTENDED_KEY_USAGE, &length);
		if (data) {
			defs = p11_parser_get_asn1_defs (parser);
			purposes = p11_x509_parse_extended_key_usage (defs, data, length);
			if (purposes == NULL)
				p11_message ("invalid extended key usage certificate extension");
			free (data);
		}

		data = p11_parsing_get_extension (parser, parsing, P11_OID_OPENSSL_REJECT, &length);
		if (data) {
			defs = p11_parser_get_asn1_defs (parser);
			rejects = p11_x509_parse_extended_key_usage (defs, data, length);
			if (rejects == NULL)
				p11_message ("invalid reject key usage certificate extension");
			free (data);
		}
	}

	/* null-terminate these arrays and use as strv's */
	purposev = rejectv = NULL;
	if (rejects) {
		if (!p11_array_push (rejects, NULL))
			return_if_reached ();
		rejectv = (const char **)rejects->elem;
	}
	if (purposes) {
		if (!p11_array_push (purposes, NULL))
			return_if_reached ();
		purposev = (const char **)purposes->elem;
	}

	build_nss_trust_object (parser, parsing, cert, trust, distrust,
	                        authority, purposev, rejectv);
	build_trust_assertions (parser, parsing, cert, trust, distrust,
	                        authority, purposev, rejectv);

	p11_array_free (purposes);
	p11_array_free (rejects);
}
