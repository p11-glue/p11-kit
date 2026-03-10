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
#include "hex.h"
#include "iter.h"
#include "message.h"
#include "options.h"
#include "tool.h"

#ifdef P11_KIT_TESTABLE
#include "mock.h"
#endif

#include <assert.h>
#include <limits.h>
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
	else if (p11_ascii_strcaseeq (type, "eddsa"))
		m.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;
	else if (p11_ascii_strcaseeq (type, "ml-dsa"))
		m.mechanism = CKM_ML_DSA_KEY_PAIR_GEN;
	else if (p11_ascii_strcaseeq (type, "ml-kem"))
		m.mechanism = CKM_ML_KEM_KEY_PAIR_GEN;
	else if (p11_ascii_strcaseeq (type, "slh-dsa"))
		m.mechanism = CKM_SLH_DSA_KEY_PAIR_GEN;

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

/* Map --parameter-set name to CKA_PARAMETER_SET value for PQC algorithms.
 * Values follow the PKCS#11 3.2 CKP_* constants. The name is the suffix
 * after the algorithm family (e.g. "65" for ML-DSA-65, "sha2-128s" for
 * SLH-DSA-SHA2-128S). */
typedef struct {
	const char *name;
	CK_ULONG value;
} ParameterSetEntry;

static const ParameterSetEntry ml_dsa_parameter_sets[] = {
	{ "44", CKP_ML_DSA_44 },
	{ "65", CKP_ML_DSA_65 },
	{ "87", CKP_ML_DSA_87 },
	{ NULL, 0 }
};

static const ParameterSetEntry ml_kem_parameter_sets[] = {
	{ "512",  CKP_ML_KEM_512 },
	{ "768",  CKP_ML_KEM_768 },
	{ "1024", CKP_ML_KEM_1024 },
	{ NULL, 0 }
};

static const ParameterSetEntry slh_dsa_parameter_sets[] = {
	{ "sha2-128s",  CKP_SLH_DSA_SHA2_128S },
	{ "shake-128s", CKP_SLH_DSA_SHAKE_128S },
	{ "sha2-128f",  CKP_SLH_DSA_SHA2_128F },
	{ "shake-128f", CKP_SLH_DSA_SHAKE_128F },
	{ "sha2-192s",  CKP_SLH_DSA_SHA2_192S },
	{ "shake-192s", CKP_SLH_DSA_SHAKE_192S },
	{ "sha2-192f",  CKP_SLH_DSA_SHA2_192F },
	{ "shake-192f", CKP_SLH_DSA_SHAKE_192F },
	{ "sha2-256s",  CKP_SLH_DSA_SHA2_256S },
	{ "shake-256s", CKP_SLH_DSA_SHAKE_256S },
	{ "sha2-256f",  CKP_SLH_DSA_SHA2_256F },
	{ "shake-256f", CKP_SLH_DSA_SHAKE_256F },
	{ NULL, 0 }
};

static CK_ULONG
get_parameter_set (CK_MECHANISM_TYPE mechanism,
		   const char *name)
{
	const ParameterSetEntry *table;
	size_t i;

	switch (mechanism) {
	case CKM_ML_DSA_KEY_PAIR_GEN:
		table = ml_dsa_parameter_sets;
		break;
	case CKM_ML_KEM_KEY_PAIR_GEN:
		table = ml_kem_parameter_sets;
		break;
	case CKM_SLH_DSA_KEY_PAIR_GEN:
		table = slh_dsa_parameter_sets;
		break;
	default:
		return 0;
	}

	for (i = 0; table[i].name != NULL; i++) {
		if (p11_ascii_strcaseeq (name, table[i].name))
			return table[i].value;
	}

	return 0;
}

static bool
check_args (CK_MECHANISM_TYPE type,
	    CK_ULONG bits,
	    const uint8_t *ec_params,
	    CK_ULONG parameter_set)
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
	case CKM_ML_DSA_KEY_PAIR_GEN:
	case CKM_ML_KEM_KEY_PAIR_GEN:
	case CKM_SLH_DSA_KEY_PAIR_GEN:
		if (parameter_set == 0) {
			p11_message (_("no parameter-set specified"));
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
	       const char *id,
	       CK_MECHANISM_TYPE type,
	       CK_ULONG bits,
	       const uint8_t *ec_params,
	       size_t ec_params_len,
	       CK_ULONG parameter_set,
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
	CK_ATTRIBUTE attr_parameter_set = { CKA_PARAMETER_SET, &parameter_set, sizeof (parameter_set) };
	CK_ATTRIBUTE attr_encapsulate = { CKA_ENCAPSULATE, &tval, sizeof (tval) };
	CK_ATTRIBUTE attr_decapsulate = { CKA_DECAPSULATE, &tval, sizeof (tval) };
	bool is_kem = (type == CKM_ML_KEM_KEY_PAIR_GEN);

	/* For KEM types, use encapsulate/decapsulate instead of verify/sign */
	pub = p11_attrs_build (NULL, &attr_token, &attr_private_false,
			       is_kem ? &attr_encapsulate : &attr_verify, NULL);
	if (pub == NULL) {
		p11_message (_("failed to allocate memory"));
		goto error;
	}
	priv = p11_attrs_build (NULL, &attr_token, &attr_private_true,
				is_kem ? &attr_decapsulate : &attr_sign, NULL);
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

	if (id != NULL) {
		size_t bin_len = 0;
		unsigned char *bin = NULL;
		CK_ATTRIBUTE attr_id = { CKA_ID, NULL, 0 };

		bin = hex_decode (id, &bin_len);
		if (bin == NULL) {
			p11_message (_("failed to decode hex value: %s"), id);
			goto error;
		}

		attr_id.pValue = (void *)bin;
		attr_id.ulValueLen = bin_len;

		tmp = p11_attrs_build (pub, &attr_id, NULL);
		if (tmp == NULL) {
			free (bin);
			p11_message (_("failed to allocate memory"));
			goto error;
		}
		pub = tmp;
		tmp = p11_attrs_build (priv, &attr_id, NULL);
		free (bin);
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
	case CKM_ML_DSA_KEY_PAIR_GEN:
	case CKM_ML_KEM_KEY_PAIR_GEN:
	case CKM_SLH_DSA_KEY_PAIR_GEN:
		tmp = p11_attrs_build (pub, &attr_parameter_set, NULL);
		if (tmp == NULL) {
			p11_message (_("failed to allocate memory"));
			goto error;
		}
		pub = tmp;
		tmp = p11_attrs_build (priv, &attr_parameter_set, NULL);
		if (tmp == NULL) {
			p11_message (_("failed to allocate memory"));
			goto error;
		}
		priv = tmp;
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
generate_keypair (p11_tool *tool,
		  const char *label,
		  const char *id,
		  CK_MECHANISM mechanism,
		  CK_ULONG bits,
		  const uint8_t *ec_params,
		  size_t ec_params_len,
		  CK_ULONG parameter_set)
{
	int ret = 1;
	CK_RV rv;
	P11KitIter *iter = NULL;
	CK_FUNCTION_LIST *module = NULL;
	CK_SESSION_HANDLE session = 0;
	CK_ATTRIBUTE *pubkey = NULL, *privkey = NULL;
	CK_OBJECT_HANDLE pubkey_obj, privkey_obj;

	if (!get_templates (label, id, mechanism.mechanism, bits,
			    ec_params, ec_params_len, parameter_set,
			    &pubkey, &privkey)) {
	        p11_message (_("failed to create key templates"));
		return 1;
	}

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
	p11_tool_end_iter (tool, iter);

	return ret;
}

int
p11_kit_generate_keypair (int argc,
			  char *argv[])
{
	int opt, ret = 2;
	const char *label = NULL;
	const char *id = NULL;
	const char *parameter_set_name = NULL;
	CK_ULONG bits = 0;
	const uint8_t *ec_params = NULL;
	size_t ec_params_len = 0;
	CK_ULONG parameter_set = 0;
	CK_MECHANISM mechanism = { CKA_INVALID, NULL_PTR, 0 };
	bool login = false;
	p11_tool *tool = NULL;
	const char *provider = NULL;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
		opt_label = 'L',
		opt_id = CHAR_MAX + 3,
		opt_type = 't',
		opt_bits = 'b',
		opt_curve = 'c',
		opt_login = 'l',
		opt_provider = CHAR_MAX + 2,
		opt_parameter_set = CHAR_MAX + 4,
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ "label", required_argument, NULL, opt_label },
		{ "id", required_argument, NULL, opt_id },
		{ "type", required_argument, NULL, opt_type },
		{ "bits", required_argument, NULL, opt_bits },
		{ "curve", required_argument, NULL, opt_curve },
		{ "parameter-set", required_argument, NULL, opt_parameter_set },
		{ "login", no_argument, NULL, opt_login },
		{ "provider", required_argument, NULL, opt_provider },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit generate-keypair [--label=<label>]"
		     " --type=<algorithm> {--bits=<n>|--curve=<name>|--parameter-set=<set>}"
		     " pkcs11:token" },
		{ opt_label, "label to be associated with generated key objects" },
		{ opt_id, "id to be associated with generated key objects" },
		{ opt_type, "type of keys to generate" },
		{ opt_bits, "number of bits for key generation" },
		{ opt_curve, "name of the curve for key generation" },
		{ opt_parameter_set, "parameter set for the key generation" },
		{ opt_login, "login to the token" },
		{ opt_provider, "specify the module to use" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_label:
			label = optarg;
			break;
		case opt_id:
			id = optarg;
			break;
		case opt_type:
			mechanism = get_mechanism (optarg);
			if (mechanism.mechanism == CKA_INVALID) {
				p11_message (_("unknown mechanism type: %s"), optarg);
				return 2;
			}
			break;
		case opt_bits:
			bits = strtol (optarg, NULL, 10);
			if (bits == 0) {
				p11_message (_("failed to parse bits value: %s"), optarg);
				return 2;
			}
			break;
		case opt_curve:
			ec_params = get_ec_params (optarg, &ec_params_len);
			if (ec_params == NULL) {
				p11_message (_("unknown curve name: %s"), optarg);
				return 2;
			}
			break;
		case opt_parameter_set:
			parameter_set_name = optarg;
			break;
		case opt_login:
			login = true;
			break;
		case opt_provider:
			provider = optarg;
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

	/* Resolve --parameter-set now that --type is known */
	if (parameter_set_name != NULL) {
		parameter_set = get_parameter_set (mechanism.mechanism, parameter_set_name);
		if (parameter_set == 0) {
			p11_message (_("unknown parameter-set: %s"), parameter_set_name);
			return 2;
		}
	}

	if (!check_args (mechanism.mechanism, bits, ec_params, parameter_set))
		return 2;

	tool = p11_tool_new ();
	if (!tool) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	if (p11_tool_set_uri (tool, *argv, P11_KIT_URI_FOR_TOKEN) != P11_KIT_URI_OK) {
		p11_message (_("failed to parse URI"));
		goto cleanup;
	}

	if (!p11_tool_set_provider (tool, provider)) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	p11_tool_set_login (tool, login);

	ret = generate_keypair (tool, label, id, mechanism, bits, ec_params, ec_params_len, parameter_set);

 cleanup:
	p11_tool_free (tool);

	return ret;
}
