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
#include "iter.h"
#include "message.h"
#include "tool.h"

#ifdef P11_KIT_TESTABLE
#include "mock.h"
#endif

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

int
p11_kit_generate_keypair (int argc,
			  char *argv[]);

static CK_MECHANISM
get_mechanism (const char *type)
{
	CK_MECHANISM m = { CKA_INVALID, NULL_PTR, 0 };

#ifdef P11_KIT_TESTABLE
	if (p11_ascii_strcaseeq (type, "mock")) {
		m.mechanism = CKM_MOCK_GENERATE;
		m.pParameter = "generate";
		m.ulParameterLen = 9;
		return m;
	}
#endif
	if (p11_ascii_strcaseeq (type, "rsa"))
		m.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	else if (p11_ascii_strcaseeq (type, "ecdsa"))
		m.mechanism = CKM_ECDSA_KEY_PAIR_GEN;
	else if (p11_ascii_strcaseeq (type, "ed25519") ||
		 p11_ascii_strcaseeq (type, "ed448"))
		m.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;

	return m;
}

static const uint8_t *
get_ec_params (const char *curve,
	       size_t *ec_params_len)
{
	static const uint8_t OID_SECP256R1[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
	static const uint8_t OID_SECP384R1[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
	static const uint8_t OID_SECP521R1[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
	static const uint8_t OID_ED25519[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };
	static const uint8_t OID_ED448[] = { 0x06, 0x03, 0x2b, 0x65, 0x71 };

	if (p11_ascii_strcaseeq (curve, "secp256r1")) {
		*ec_params_len = sizeof (OID_SECP256R1);
		return OID_SECP256R1;
	} else if (p11_ascii_strcaseeq (curve, "secp384r1")) {
		*ec_params_len = sizeof (OID_SECP384R1);
		return OID_SECP384R1;
	} else if (p11_ascii_strcaseeq (curve, "secp521r1")) {
		*ec_params_len = sizeof (OID_SECP521R1);
		return OID_SECP521R1;
	} else if (p11_ascii_strcaseeq (curve, "ed25519")) {
		*ec_params_len = sizeof (OID_ED25519);
		return OID_ED25519;
	} else if (p11_ascii_strcaseeq (curve, "ed448")) {
		*ec_params_len = sizeof (OID_ED448);
		return OID_ED448;
	}

	return NULL;
}

static bool
check_args (CK_MECHANISM_TYPE type,
	    CK_ULONG bits,
	    const uint8_t *ec_params)
{
	switch (type) {
#ifdef P11_KIT_TESTABLE
	case CKM_MOCK_GENERATE:
		break;
#endif
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		if (bits == 0) {
			p11_message (_("no bits specified"));
			return false;
		}
		break;
	case CKM_ECDSA_KEY_PAIR_GEN:
	case CKM_EC_EDWARDS_KEY_PAIR_GEN:
		if (ec_params == NULL) {
			p11_message (_("no curve specified"));
			return false;
		}
		break;
	case CKA_INVALID:
		p11_message (_("no type specified"));
		return false;
	default:
		p11_message (_("unkwnown mechanism type in %s"), __func__);
		return false;
	}

	if (bits != 0 && ec_params != NULL) {
		p11_message (_("both %s and %s cannot be specified at once"), "--bits", "--curve");
		return false;
	}

	return true;
}

static bool
get_templates (const char *label,
	       CK_MECHANISM_TYPE type,
	       CK_ULONG bits,
	       const uint8_t *ec_params,
	       size_t ec_params_len,
	       CK_ATTRIBUTE **pubkey,
	       CK_ATTRIBUTE **privkey)
{
	CK_BBOOL tval = CK_TRUE, fval = CK_FALSE;
	CK_ATTRIBUTE *pub = NULL, *priv = NULL, *tmp;
	CK_ATTRIBUTE attr_token = { CKA_TOKEN, &tval, sizeof (tval) };
	CK_ATTRIBUTE attr_private_true = { CKA_PRIVATE, &tval, sizeof (tval) };
	CK_ATTRIBUTE attr_private_false = { CKA_PRIVATE, &fval, sizeof (fval) };
	CK_ATTRIBUTE attr_sign = { CKA_SIGN, &tval, sizeof (tval) };
	CK_ATTRIBUTE attr_verify = { CKA_VERIFY, &tval, sizeof (tval) };
	CK_ATTRIBUTE attr_decrypt = { CKA_DECRYPT, &tval, sizeof (tval) };
	CK_ATTRIBUTE attr_encrypt = { CKA_ENCRYPT, &tval, sizeof (tval) };
	CK_ATTRIBUTE attr_modulus = { CKA_MODULUS_BITS, &bits, sizeof (bits) };
	CK_ATTRIBUTE attr_ec_params = { CKA_EC_PARAMS, (void *)ec_params, ec_params_len };

	pub = p11_attrs_build (NULL, &attr_token, &attr_private_false, &attr_verify, NULL);
	if (pub == NULL) {
		p11_message (_("failed to allocate memory"));
		goto error;
	}
	priv = p11_attrs_build (NULL, &attr_token, &attr_private_true, &attr_sign, NULL);
	if (priv == NULL) {
		p11_message (_("failed to allocate memory"));
		goto error;
	}

	if (label != NULL) {
		CK_ATTRIBUTE attr_label = { CKA_LABEL, (void *)label, strlen (label) };

		tmp = p11_attrs_build (pub, &attr_label, NULL);
		if (tmp == NULL) {
			p11_message (_("failed to allocate memory"));
			goto error;
		}
		pub = tmp;
		tmp = p11_attrs_build (priv, &attr_label, NULL);
		if (tmp == NULL) {
			p11_message (_("failed to allocate memory"));
			goto error;
		}
		priv = tmp;
	}

	switch (type) {
#ifdef P11_KIT_TESTABLE
	case CKM_MOCK_GENERATE:
		break;
#endif
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		tmp = p11_attrs_build (pub, &attr_encrypt, &attr_modulus, NULL);
		if (tmp == NULL) {
			p11_message (_("failed to allocate memory"));
			goto error;
		}
		pub = tmp;
		tmp = p11_attrs_build (priv, &attr_decrypt, NULL);
		if (tmp == NULL) {
			p11_message (_("failed to allocate memory"));
			goto error;
		}
		priv = tmp;
		break;
	case CKM_ECDSA_KEY_PAIR_GEN:
	case CKM_EC_EDWARDS_KEY_PAIR_GEN:
		tmp = p11_attrs_build (pub, &attr_ec_params, NULL);
		if (tmp == NULL) {
			p11_message (_("failed to allocate memory"));
			goto error;
		}
		pub = tmp;
		break;
	default:
		p11_message (_("unkwnown mechanism type in %s"), __func__);
		goto error;
	}

	*pubkey = pub;
	*privkey = priv;

	return true;
error:
	p11_attrs_free (pub);
	p11_attrs_free (priv);

	return false;
}

static int
generate_keypair (const char *token_str,
		  const char *label,
		  CK_MECHANISM mechanism,
		  CK_ULONG bits,
		  const uint8_t *ec_params,
		  size_t ec_params_len)
{
	int ret = 1;
	CK_RV rv;
	P11KitUri *uri = NULL;
	P11KitIter *iter = NULL;
	P11KitIterBehavior behavior;
	CK_FUNCTION_LIST **modules = NULL;
	CK_FUNCTION_LIST *module = NULL;
	CK_SESSION_HANDLE session = 0;
	CK_ATTRIBUTE *pubkey = NULL, *privkey = NULL;
	CK_OBJECT_HANDLE pubkey_obj, privkey_obj;

	if (!get_templates (label, mechanism.mechanism, bits,
			    ec_params, ec_params_len, &pubkey, &privkey)) {
	        p11_message (_("failed to create key templates"));
		goto cleanup;
	}

	uri = p11_kit_uri_new ();
	if (uri == NULL) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	if (p11_kit_uri_parse (token_str, P11_KIT_URI_FOR_TOKEN, uri) != P11_KIT_URI_OK) {
		p11_message (_("failed to parse URI"));
		goto cleanup;
	}

	modules = p11_kit_modules_load_and_initialize (0);
	if (modules == NULL) {
		p11_message (_("failed to load and initialize modules"));
		goto cleanup;
	}

	behavior = P11_KIT_ITER_WANT_WRITABLE | P11_KIT_ITER_WITH_TOKENS | P11_KIT_ITER_WITHOUT_OBJECTS;
	if (p11_kit_uri_get_pin_value (uri))
		behavior |= P11_KIT_ITER_WITH_LOGIN;
	iter = p11_kit_iter_new (uri, behavior);
	if (iter == NULL) {
		p11_message (_("failed to initialize iterator"));
		goto cleanup;
	}

	p11_kit_iter_begin (iter, modules);
	rv = p11_kit_iter_next (iter);
	if (rv != CKR_OK) {
		if (rv == CKR_CANCEL)
			p11_message (_("no matching token"));
		else
			p11_message (_("failed to find token: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	/* Module and session should always be set at this point.  */
	module = p11_kit_iter_get_module (iter);
	return_val_if_fail (module != NULL, 1);
	session = p11_kit_iter_get_session (iter);
	return_val_if_fail (session != CK_INVALID_HANDLE, 1);

	rv = module->C_GenerateKeyPair (session, &mechanism,
					pubkey, p11_attrs_count (pubkey),
					privkey, p11_attrs_count (privkey),
					&pubkey_obj, &privkey_obj);
	if (rv != CKR_OK) {
		p11_message (_("key-pair generation failed: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	ret = 0;

cleanup:
	p11_attrs_free (pubkey);
	p11_attrs_free (privkey);
	p11_kit_iter_free (iter);
	p11_kit_uri_free (uri);
	if (modules != NULL)
		p11_kit_modules_finalize_and_release (modules);

	return ret;
}

int
p11_kit_generate_keypair (int argc,
			  char *argv[])
{
	int opt, ret = 2;
	char *label = NULL;
	CK_ULONG bits = 0;
	const uint8_t *ec_params = NULL;
	size_t ec_params_len = 0;
	CK_MECHANISM mechanism = { CKA_INVALID, NULL_PTR, 0 };

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
		opt_label = 'l',
		opt_type = 't',
		opt_bits = 'b',
		opt_curve = 'c',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ "label", required_argument, NULL, opt_label },
		{ "type", required_argument, NULL, opt_type },
		{ "bits", required_argument, NULL, opt_bits },
		{ "curve", required_argument, NULL, opt_curve },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit generate-keypair [--label=<label>]"
		     " --type=<algorithm> {--bits=<n>|--curve=<name>} pkcs11:token" },
		{ opt_label, "label to be associated with generated key objects" },
		{ opt_type, "type of keys to generate" },
		{ opt_bits, "number of bits for key generation" },
		{ opt_curve, "name of the curve for key generation" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_label:
			label = strdup (optarg);
			if (label == NULL) {
				p11_message (_("failed to allocate memory"));
				goto cleanup;
			}
			break;
		case opt_type:
			mechanism = get_mechanism (optarg);
			if (mechanism.mechanism == CKA_INVALID) {
				p11_message (_("unknown mechanism type: %s"), optarg);
				goto cleanup;
			}
			break;
		case opt_bits:
			bits = strtol (optarg, NULL, 10);
			if (bits == 0) {
				p11_message (_("failed to parse bits value: %s"), optarg);
				goto cleanup;
			}
			break;
		case opt_curve:
			ec_params = get_ec_params (optarg, &ec_params_len);
			if (ec_params == NULL) {
				p11_message (_("unknown curve name: %s"), optarg);
				goto cleanup;
			}
			break;
		case opt_verbose:
			p11_kit_be_loud ();
			break;
		case opt_quiet:
			p11_kit_be_quiet ();
			break;
		case opt_help:
			p11_tool_usage (usages, options);
			ret = 0;
			goto cleanup;
		case '?':
			goto cleanup;
		default:
			assert_not_reached ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		p11_tool_usage (usages, options);
		goto cleanup;
	}

	if (!check_args (mechanism.mechanism, bits, ec_params))
		goto cleanup;

	ret = generate_keypair (*argv, label, mechanism, bits, ec_params, ec_params_len);

cleanup:
	free (label);

	return ret;
}
