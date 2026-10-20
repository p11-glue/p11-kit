/*
 * Copyright (C) 2008 Stefan Walter
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#define P11_DEBUG_FLAG P11_DEBUG_RPC
#include "debug.h"
#include "private.h"
#include "rpc.h"
#include "rpc-attribute.h"
#include "rpc-mechanism.h"

#include <assert.h>
#include <string.h>

#define ELEMS(x) (sizeof (x) / sizeof (x[0]))

/* Used to override the supported mechanisms in tests */
CK_MECHANISM_TYPE *p11_rpc_mechanisms_override_supported = NULL;

typedef struct {
	CK_MECHANISM_TYPE type;
	p11_rpc_value_encoder encode;
	p11_rpc_value_decoder decode;
} p11_rpc_mechanism_serializer;

/*
 * Convert a bit count into the number of bytes needed to hold it.
 * Returns false on overflow.
 */
static bool
bits_to_bytes (CK_ULONG bits,
	       size_t *bytes)
{
	if (bits > (CK_ULONG) - 8)
		return false;

	*bytes = (size_t) ((bits + 7) / 8);
	return true;
}

void
p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value (p11_buffer *buffer,
						 const void *value,
						 CK_ULONG value_length)
{
	CK_RSA_PKCS_PSS_PARAMS params;

	if (value_length != sizeof (CK_RSA_PKCS_PSS_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.hashAlg);
	p11_rpc_buffer_add_uint64 (buffer, params.mgf);
	p11_rpc_buffer_add_uint64 (buffer, params.sLen);
}

bool
p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value (p11_buffer *buffer,
						 size_t *offset,
						 void *value,
						 CK_ULONG *value_length)
{
	CK_RSA_PKCS_PSS_PARAMS params;
	uint64_t hash_alg, mgf, s_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &hash_alg) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &mgf) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &s_len))
		return false;

	if (value) {
		params.hashAlg = hash_alg;
		params.mgf = mgf;
		params.sLen = s_len;

		memcpy (value, &params, sizeof (CK_RSA_PKCS_PSS_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_RSA_PKCS_PSS_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_rsa_pkcs_oaep_mechanism_value (p11_buffer *buffer,
						  const void *value,
						  CK_ULONG value_length)
{
	CK_RSA_PKCS_OAEP_PARAMS params;

	if (value_length != sizeof (CK_RSA_PKCS_OAEP_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.hashAlg);
	p11_rpc_buffer_add_uint64 (buffer, params.mgf);
	p11_rpc_buffer_add_uint64 (buffer, params.source);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.pSourceData,
				       params.ulSourceDataLen);
}

bool
p11_rpc_buffer_get_rsa_pkcs_oaep_mechanism_value (p11_buffer *buffer,
						  size_t *offset,
						  void *value,
						  CK_ULONG *value_length)
{
	CK_RSA_PKCS_OAEP_PARAMS params;
	uint64_t hash_alg, mgf, source;
	const unsigned char *source_data;
	size_t source_data_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &hash_alg) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &mgf) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &source) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &source_data, &source_data_len))
		return false;

	if (value) {
		params.hashAlg = hash_alg;
		params.mgf = mgf;
		params.source = source;
		params.pSourceData = (void *) source_data;
		params.ulSourceDataLen = source_data_len;

		memcpy (value, &params, sizeof (CK_RSA_PKCS_OAEP_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_RSA_PKCS_OAEP_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ecdh1_derive_mechanism_value (p11_buffer *buffer,
						 const void *value,
						 CK_ULONG value_length)
{
	CK_ECDH1_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_ECDH1_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.kdf);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.pSharedData,
				       params.ulSharedDataLen);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.pPublicData,
				       params.ulPublicDataLen);
}

bool
p11_rpc_buffer_get_ecdh1_derive_mechanism_value (p11_buffer *buffer,
						 size_t *offset,
						 void *value,
						 CK_ULONG *value_length)
{
	CK_ECDH1_DERIVE_PARAMS params;
	uint64_t kdf;
	const unsigned char *shared_data, *public_data;
	size_t shared_data_len, public_data_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &kdf) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &shared_data, &shared_data_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &public_data, &public_data_len))
		return false;

	if (value) {
		params.kdf = kdf;
		params.pSharedData = (void *) shared_data;
		params.ulSharedDataLen = shared_data_len;
		params.pPublicData = (void *) public_data;
		params.ulPublicDataLen = public_data_len;

		memcpy (value, &params, sizeof (CK_ECDH1_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_ECDH1_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ibm_attrbound_wrap_mechanism_value (p11_buffer *buffer,
						       const void *value,
						       CK_ULONG value_length)
{
	CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS params;

	if (value_length != sizeof (CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.hSignVerifyKey);
}

bool
p11_rpc_buffer_get_ibm_attrbound_wrap_mechanism_value (p11_buffer *buffer,
						       size_t *offset,
						       void *value,
						       CK_ULONG *value_length)
{
	CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS params;
	uint64_t sign_verify_key;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &sign_verify_key))
		return false;

	if (value) {
		params.hSignVerifyKey = sign_verify_key;

		memcpy (value, &params, sizeof (CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ibm_kyber_mech_param_update (p11_buffer *buffer,
						const void *value,
						CK_ULONG value_length)
{
	CK_IBM_KYBER_PARAMS params;

	if (value_length != sizeof (CK_IBM_KYBER_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	if (params.mode == CK_IBM_KYBER_KEM_ENCAPSULATE) {
		p11_rpc_buffer_add_byte (buffer, CK_IBM_KYBER_KEM_ENCAPSULATE);

		if (params.pCipher == NULL) {
			p11_rpc_buffer_add_byte (buffer, 0);
			p11_rpc_buffer_add_uint32 (buffer, params.ulCipherLen);
		} else {
			p11_rpc_buffer_add_byte (buffer, 1);
			p11_rpc_buffer_add_byte_array (buffer,
						       (unsigned char *) params.pCipher,
						       params.ulCipherLen);
		}
	} else {
		p11_rpc_buffer_add_byte (buffer, CK_IBM_KYBER_KEM_DECAPSULATE);
	}
}

bool
p11_rpc_buffer_get_ibm_kyber_mech_param_update (p11_buffer *buffer,
						size_t *offset,
						void *value,
						CK_ULONG *value_length)
{
	uint32_t length;
	unsigned char has_data;
	unsigned char capsulation;
	const unsigned char *cipher;
	size_t cipher_len;

	if (!p11_rpc_buffer_get_byte (buffer, offset, &capsulation))
		return false;

	if (capsulation == CK_IBM_KYBER_KEM_ENCAPSULATE) {
		if (!p11_rpc_buffer_get_byte (buffer, offset, &has_data))
			return false;

		if (has_data) {
			if (!p11_rpc_buffer_get_byte_array (buffer, offset,
							    &cipher, &cipher_len))
				return false;
		} else {
			if (!p11_rpc_buffer_get_uint32 (buffer, offset, &length))
				return false;
			cipher_len = length;
		}

		if (value) {
			CK_IBM_KYBER_PARAMS *params = (CK_IBM_KYBER_PARAMS *) value;

			if (has_data) {
				assert (cipher != NULL);

				if (params->pCipher &&
				    params->ulCipherLen == cipher_len)
					memcpy (params->pCipher, cipher,
						cipher_len);
				else
					params->pCipher = (void *) cipher;
			}
			params->ulCipherLen = cipher_len;
		}
	}

	if (value_length)
		*value_length = sizeof (CK_IBM_KYBER_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ibm_btc_derive_mech_param_update (p11_buffer *buffer,
						     const void *value,
						     CK_ULONG value_length)
{
	CK_IBM_BTC_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_IBM_BTC_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	if (params.pChainCode == NULL) {
		p11_rpc_buffer_add_byte (buffer, 0);
		p11_rpc_buffer_add_uint32 (buffer, params.ulChainCodeLen);
	} else {
		p11_rpc_buffer_add_byte (buffer, 1);
		p11_rpc_buffer_add_byte_array (buffer,
					       (unsigned char *) params.pChainCode,
					       params.ulChainCodeLen);
	}
}

bool
p11_rpc_buffer_get_ibm_btc_derive_mech_param_update (p11_buffer *buffer,
						     size_t *offset,
						     void *value,
						     CK_ULONG *value_length)
{
	uint32_t length;
	unsigned char has_data;
	const unsigned char *chain_code;
	size_t chain_code_len;

	if (!p11_rpc_buffer_get_byte (buffer, offset, &has_data))
		return false;

	if (has_data) {
		if (!p11_rpc_buffer_get_byte_array (buffer, offset,
						    &chain_code, &chain_code_len))
			return false;
	} else {
		if (!p11_rpc_buffer_get_uint32 (buffer, offset, &length))
			return false;
		chain_code_len = length;
	}

	if (value) {
		CK_IBM_BTC_DERIVE_PARAMS *params = (CK_IBM_BTC_DERIVE_PARAMS *) value;

		if (has_data) {
			assert (chain_code != NULL);

			if (params->pChainCode &&
			    params->ulChainCodeLen == chain_code_len)
				memcpy (params->pChainCode, chain_code,
					chain_code_len);
			else
				params->pChainCode = (void *) chain_code;
		}
		params->ulChainCodeLen = chain_code_len;
	}

	if (value_length)
		*value_length = sizeof (CK_IBM_BTC_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ibm_ecdsa_other_mechanism_value (p11_buffer *buffer,
						    const void *value,
						    CK_ULONG value_length)
{
	CK_IBM_ECDSA_OTHER_PARAMS params;

	if (value_length != sizeof (CK_IBM_ECDSA_OTHER_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.submechanism);
}

bool
p11_rpc_buffer_get_ibm_ecdsa_other_mechanism_value (p11_buffer *buffer,
						    size_t *offset,
						    void *value,
						    CK_ULONG *value_length)
{
	CK_IBM_ECDSA_OTHER_PARAMS params;
	uint64_t submechanism;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &submechanism))
		return false;

	if (value) {
		params.submechanism = submechanism;

		memcpy (value, &params, sizeof (CK_IBM_ECDSA_OTHER_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_IBM_ECDSA_OTHER_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ibm_btc_derive_mechanism_value (p11_buffer *buffer,
						   const void *value,
						   CK_ULONG value_length)
{
	CK_IBM_BTC_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_IBM_BTC_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.type);
	p11_rpc_buffer_add_uint64 (buffer, params.childKeyIndex);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.pChainCode,
				       params.ulChainCodeLen);
	p11_rpc_buffer_add_uint64 (buffer, params.version);
}

bool
p11_rpc_buffer_get_ibm_btc_derive_mechanism_value (p11_buffer *buffer,
						   size_t *offset,
						   void *value,
						   CK_ULONG *value_length)
{
	CK_IBM_BTC_DERIVE_PARAMS params;
	uint64_t type, child_key_index, version;
	const unsigned char *chain_code;
	size_t chain_code_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &type) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &child_key_index) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &chain_code, &chain_code_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &version))
		return false;

	if (value) {
		params.type = type;
		params.childKeyIndex = child_key_index;
		params.ulChainCodeLen = chain_code_len;
		params.pChainCode = (void *) chain_code;
		params.version = version;

		memcpy (value, &params, sizeof (CK_IBM_BTC_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_IBM_BTC_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ibm_kyber_mechanism_value (p11_buffer *buffer,
					      const void *value,
					      CK_ULONG value_length)
{
	CK_IBM_KYBER_PARAMS params;

	if (value_length != sizeof (CK_IBM_KYBER_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.ulVersion);
	p11_rpc_buffer_add_uint64 (buffer, params.mode);
	p11_rpc_buffer_add_uint64 (buffer, params.kdf);

	if (params.bPrepend > sizeof (CK_BBOOL)) {
		p11_buffer_fail (buffer);
		return;
	}
	p11_rpc_buffer_add_byte (buffer, (unsigned char) params.bPrepend);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.pCipher,
				       params.ulCipherLen);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.pSharedData,
				       params.ulSharedDataLen);

	if (params.hSecret > sizeof (CK_OBJECT_HANDLE)) {
		p11_buffer_fail (buffer);
		return;
	}
	p11_rpc_buffer_add_uint64 (buffer, params.hSecret);
}

bool
p11_rpc_buffer_get_ibm_kyber_mechanism_value (p11_buffer *buffer,
					      size_t *offset,
					      void *value,
					      CK_ULONG *value_length)
{
	uint64_t version, mode, kdf, secret;
	unsigned char prepend;
	const unsigned char *cipher, *shared_data;
	size_t cipher_len, shared_data_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &version) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &mode) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &kdf) ||
	    !p11_rpc_buffer_get_byte (buffer, offset, &prepend) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &cipher, &cipher_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &shared_data, &shared_data_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &secret))
		return false;

	if (value) {
		CK_IBM_KYBER_PARAMS *params = (CK_IBM_KYBER_PARAMS *) value;

		params->ulVersion = version;
		params->mode = mode;
		params->kdf = kdf;
		params->bPrepend = prepend;
		if (params->pCipher && params->ulCipherLen == cipher_len) {
			memcpy (params->pCipher, cipher, cipher_len);
			params->ulCipherLen = cipher_len;
		} else {
			params->pCipher = (void *) cipher;
			params->ulCipherLen = cipher_len;
		}
		if (params->pSharedData && params->ulSharedDataLen == shared_data_len) {
			memcpy (params->pSharedData, shared_data, shared_data_len);
			params->ulSharedDataLen = shared_data_len;
		} else {
			params->pSharedData = (void *) shared_data;
			params->ulSharedDataLen = shared_data_len;
		}
		params->hSecret = secret;
	}

	if (value_length)
		*value_length = sizeof (CK_IBM_KYBER_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_aes_iv_mechanism_value (p11_buffer *buffer,
					   const void *value,
					   CK_ULONG value_length)
{
	if (value_length != 16) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) value,
				       value_length);
}

bool
p11_rpc_buffer_get_aes_iv_mechanism_value (p11_buffer *buffer,
					   size_t *offset,
					   void *value,
					   CK_ULONG *value_length)
{
	const unsigned char *iv;
	size_t iv_len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &iv, &iv_len))
		return false;

	if (iv_len != 16)
		return false;

	if (value)
		memcpy (value, iv, iv_len);

	if (value_length)
		*value_length = iv_len;

	return true;
}

void
p11_rpc_buffer_add_aes_ctr_mechanism_value (p11_buffer *buffer,
					    const void *value,
					    CK_ULONG value_length)
{
	CK_AES_CTR_PARAMS params;

	if (value_length != sizeof (CK_AES_CTR_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.ulCounterBits);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.cb,
				       sizeof (params.cb));
}

bool
p11_rpc_buffer_get_aes_ctr_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	CK_AES_CTR_PARAMS params;
	uint64_t counter_bits;
	const unsigned char *cb;
	size_t cb_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &counter_bits) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &cb, &cb_len))
		return false;

	if (cb_len != sizeof (params.cb))
		return false;

	if (value) {
		params.ulCounterBits = counter_bits;
		memcpy (params.cb, cb, sizeof (params.cb));

		memcpy (value, &params, sizeof (CK_AES_CTR_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_AES_CTR_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_aes_gcm_mechanism_value (p11_buffer *buffer,
					    const void *value,
					    CK_ULONG value_length)
{
	CK_GCM_PARAMS params;

	if (value_length != sizeof (CK_GCM_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.pIv,
				       params.ulIvLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulIvBits);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.pAAD,
				       params.ulAADLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulTagBits);
}

bool
p11_rpc_buffer_get_aes_gcm_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	CK_GCM_PARAMS params;
	uint64_t iv_bits, tag_bits;
	const unsigned char *iv, *aad;
	size_t iv_len, aad_len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &iv, &iv_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &iv_bits) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &aad, &aad_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &tag_bits))
		return false;

	if (value) {
		params.pIv = (void *) iv;
		params.ulIvLen = iv_len;
		params.ulIvBits = iv_bits;
		params.pAAD = (void *) aad;
		params.ulAADLen = aad_len;
		params.ulTagBits = tag_bits;

		memcpy (value, &params, sizeof (CK_GCM_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_GCM_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_des_iv_mechanism_value (p11_buffer *buffer,
					   const void *value,
					   CK_ULONG value_length)
{
	if (value_length != 8) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) value,
				       value_length);
}

bool
p11_rpc_buffer_get_des_iv_mechanism_value (p11_buffer *buffer,
					   size_t *offset,
					   void *value,
					   CK_ULONG *value_length)
{
	const unsigned char *iv;
	size_t iv_len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &iv, &iv_len))
		return false;

	if (iv_len != 8)
		return false;

	if (value)
		memcpy (value, iv, iv_len);

	if (value_length)
		*value_length = iv_len;

	return true;
}

void
p11_rpc_buffer_add_mac_general_mechanism_value (p11_buffer *buffer,
						const void *value,
						CK_ULONG value_length)
{
	CK_ULONG params;

	/*
	 * Check if value can be converted to a CK_MAC_GENERAL_PARAMS,
	 * which is a CK_ULONG.
	 */
	if (value_length != sizeof (CK_ULONG)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params);
}

bool
p11_rpc_buffer_get_mac_general_mechanism_value (p11_buffer *buffer,
						size_t *offset,
						void *value,
						CK_ULONG *value_length)
{
	CK_ULONG params;
	uint64_t mac_length;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &mac_length))
		return false;

	params = mac_length;

	if (value)
		memcpy (value, &params, sizeof (params));

	if (value_length)
		*value_length = sizeof (params);

	return true;
}

void
p11_rpc_buffer_add_dh_pkcs_derive_mechanism_value (p11_buffer *buffer,
						   const void *value,
						   CK_ULONG value_length)
{
	/* Mechanism parameter is public value of the other party */
	if (value_length == 0) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) value,
				       value_length);
}

bool
p11_rpc_buffer_get_dh_pkcs_derive_mechanism_value (p11_buffer *buffer,
						   size_t *offset,
						   void *value,
						   CK_ULONG *value_length)
{
	const unsigned char *public_value;
	size_t public_value_len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset,
					    &public_value, &public_value_len))
		return false;

	if (public_value_len == 0)
		return false;

	if (value)
		memcpy (value, public_value, public_value_len);

	if (value_length)
		*value_length = public_value_len;

	return true;
}

void
p11_rpc_buffer_add_eddsa_mechanism_value (p11_buffer *buffer,
					  const void *value,
					  CK_ULONG value_length)
{
	CK_EDDSA_PARAMS params;

	if (value_length != sizeof (CK_EDDSA_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_byte (buffer, params.phFlag ? 1 : 0);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.pContextData,
				       params.ulContextDataLen);
}

bool
p11_rpc_buffer_get_eddsa_mechanism_value (p11_buffer *buffer,
					  size_t *offset,
					  void *value,
					  CK_ULONG *value_length)
{
	CK_EDDSA_PARAMS params;
	unsigned char flag;
	const unsigned char *context_data;
	size_t context_data_len;

	if (!p11_rpc_buffer_get_byte (buffer, offset, &flag) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &context_data, &context_data_len))
		return false;

	if (value) {
		params.phFlag = flag ? CK_TRUE : CK_FALSE;
		params.pContextData = (void *) context_data;
		params.ulContextDataLen = context_data_len;

		memcpy (value, &params, sizeof (CK_EDDSA_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_EDDSA_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_sign_additional_context_mechanism_value (p11_buffer *buffer,
							    const void *value,
							    CK_ULONG value_length)
{
	CK_SIGN_ADDITIONAL_CONTEXT params;

	if (value_length != sizeof (CK_SIGN_ADDITIONAL_CONTEXT)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.hedgeVariant);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.pContext,
				       params.ulContextLen);
}

bool
p11_rpc_buffer_get_sign_additional_context_mechanism_value (p11_buffer *buffer,
							    size_t *offset,
							    void *value,
							    CK_ULONG *value_length)
{
	CK_SIGN_ADDITIONAL_CONTEXT params;
	uint64_t hedge_variant;
	const unsigned char *context;
	size_t context_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &hedge_variant) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &context, &context_len))
		return false;

	if (value) {
		params.hedgeVariant = hedge_variant;
		params.pContext = (void *) context;
		params.ulContextLen = context_len;

		memcpy (value, &params, sizeof (CK_SIGN_ADDITIONAL_CONTEXT));
	}

	if (value_length)
		*value_length = sizeof (CK_SIGN_ADDITIONAL_CONTEXT);

	return true;
}

void
p11_rpc_buffer_add_hash_sign_additional_context_mechanism_value (p11_buffer *buffer,
								 const void *value,
								 CK_ULONG value_length)
{
	CK_HASH_SIGN_ADDITIONAL_CONTEXT params;

	if (value_length != sizeof (CK_HASH_SIGN_ADDITIONAL_CONTEXT)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.hedgeVariant);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *) params.pContext,
				       params.ulContextLen);
	p11_rpc_buffer_add_uint64 (buffer, params.hash);
}

bool
p11_rpc_buffer_get_hash_sign_additional_context_mechanism_value (p11_buffer *buffer,
								 size_t *offset,
								 void *value,
								 CK_ULONG *value_length)
{
	CK_HASH_SIGN_ADDITIONAL_CONTEXT params;
	uint64_t hedge_variant, hash;
	const unsigned char *context;
	size_t context_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &hedge_variant) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &context, &context_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &hash))
		return false;

	if (value) {
		params.hedgeVariant = hedge_variant;
		params.pContext = (void *) context;
		params.ulContextLen = context_len;
		params.hash = hash;

		memcpy (value, &params, sizeof (CK_HASH_SIGN_ADDITIONAL_CONTEXT));
	}

	if (value_length)
		*value_length = sizeof (CK_HASH_SIGN_ADDITIONAL_CONTEXT);

	return true;
}

void
p11_rpc_buffer_add_rc2_cbc_mechanism_value (p11_buffer *buffer,
					    const void *value,
					    CK_ULONG value_length)
{
	CK_RC2_CBC_PARAMS params;

	if (value_length != sizeof (CK_RC2_CBC_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.ulEffectiveBits);
	p11_rpc_buffer_add_byte_array (buffer, params.iv, sizeof (params.iv));
}

bool
p11_rpc_buffer_get_rc2_cbc_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	CK_RC2_CBC_PARAMS params;
	uint64_t effective_bits;
	const unsigned char *iv;
	size_t iv_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &effective_bits) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &iv, &iv_len))
		return false;

	if (iv_len != sizeof (params.iv))
		return false;

	if (value) {
		params.ulEffectiveBits = effective_bits;
		memcpy (params.iv, iv, sizeof (params.iv));

		memcpy (value, &params, sizeof (CK_RC2_CBC_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_RC2_CBC_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_rc2_mac_general_mechanism_value (p11_buffer *buffer,
						    const void *value,
						    CK_ULONG value_length)
{
	CK_RC2_MAC_GENERAL_PARAMS params;

	if (value_length != sizeof (CK_RC2_MAC_GENERAL_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.ulEffectiveBits);
	p11_rpc_buffer_add_uint64 (buffer, params.ulMacLength);
}

bool
p11_rpc_buffer_get_rc2_mac_general_mechanism_value (p11_buffer *buffer,
						    size_t *offset,
						    void *value,
						    CK_ULONG *value_length)
{
	CK_RC2_MAC_GENERAL_PARAMS params;
	uint64_t effective_bits, mac_length;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &effective_bits) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &mac_length))
		return false;

	if (value) {
		params.ulEffectiveBits = effective_bits;
		params.ulMacLength = mac_length;

		memcpy (value, &params, sizeof (CK_RC2_MAC_GENERAL_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_RC2_MAC_GENERAL_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_rc5_cbc_mechanism_value (p11_buffer *buffer,
					    const void *value,
					    CK_ULONG value_length)
{
	CK_RC5_CBC_PARAMS params;

	if (value_length != sizeof (CK_RC5_CBC_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.ulWordsize);
	p11_rpc_buffer_add_uint64 (buffer, params.ulRounds);
	p11_rpc_buffer_add_byte_array (buffer, params.pIv, params.ulIvLen);
}

bool
p11_rpc_buffer_get_rc5_cbc_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	CK_RC5_CBC_PARAMS params;
	uint64_t wordsize, rounds;
	const unsigned char *iv;
	size_t iv_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &wordsize) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &rounds) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &iv, &iv_len))
		return false;

	if (value) {
		params.ulWordsize = wordsize;
		params.ulRounds = rounds;
		params.pIv = (CK_BYTE_PTR) iv;
		params.ulIvLen = iv_len;

		memcpy (value, &params, sizeof (CK_RC5_CBC_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_RC5_CBC_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_rc5_mac_general_mechanism_value (p11_buffer *buffer,
						    const void *value,
						    CK_ULONG value_length)
{
	CK_RC5_MAC_GENERAL_PARAMS params;

	if (value_length != sizeof (CK_RC5_MAC_GENERAL_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.ulWordsize);
	p11_rpc_buffer_add_uint64 (buffer, params.ulRounds);
	p11_rpc_buffer_add_uint64 (buffer, params.ulMacLength);
}

bool
p11_rpc_buffer_get_rc5_mac_general_mechanism_value (p11_buffer *buffer,
						    size_t *offset,
						    void *value,
						    CK_ULONG *value_length)
{
	CK_RC5_MAC_GENERAL_PARAMS params;
	uint64_t wordsize, rounds, mac_length;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &wordsize) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &rounds) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &mac_length))
		return false;

	if (value) {
		params.ulWordsize = wordsize;
		params.ulRounds = rounds;
		params.ulMacLength = mac_length;

		memcpy (value, &params, sizeof (CK_RC5_MAC_GENERAL_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_RC5_MAC_GENERAL_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_xeddsa_mechanism_value (p11_buffer *buffer,
					   const void *value,
					   CK_ULONG value_length)
{
	CK_XEDDSA_PARAMS params;

	if (value_length != sizeof (CK_XEDDSA_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.hash);
}

bool
p11_rpc_buffer_get_xeddsa_mechanism_value (p11_buffer *buffer,
					   size_t *offset,
					   void *value,
					   CK_ULONG *value_length)
{
	CK_XEDDSA_PARAMS params;
	uint64_t hash;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &hash))
		return false;

	if (value) {
		params.hash = hash;

		memcpy (value, &params, sizeof (CK_XEDDSA_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_XEDDSA_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_dsa_parameter_gen_mechanism_value (p11_buffer *buffer,
						      const void *value,
						      CK_ULONG value_length)
{
	CK_DSA_PARAMETER_GEN_PARAM params;

	if (value_length != sizeof (CK_DSA_PARAMETER_GEN_PARAM)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.hash);
	p11_rpc_buffer_add_byte_array (buffer, params.pSeed, params.ulSeedLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulIndex);
}

bool
p11_rpc_buffer_get_dsa_parameter_gen_mechanism_value (p11_buffer *buffer,
						      size_t *offset,
						      void *value,
						      CK_ULONG *value_length)
{
	CK_DSA_PARAMETER_GEN_PARAM params;
	uint64_t hash, index;
	const unsigned char *seed;
	size_t seed_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &hash) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &seed, &seed_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &index))
		return false;

	if (value) {
		params.hash = hash;
		params.pSeed = (CK_BYTE_PTR) seed;
		params.ulSeedLen = seed_len;
		params.ulIndex = index;

		memcpy (value, &params, sizeof (CK_DSA_PARAMETER_GEN_PARAM));
	}

	if (value_length)
		*value_length = sizeof (CK_DSA_PARAMETER_GEN_PARAM);

	return true;
}

void
p11_rpc_buffer_add_ecdh_aes_key_wrap_mechanism_value (p11_buffer *buffer,
						      const void *value,
						      CK_ULONG value_length)
{
	CK_ECDH_AES_KEY_WRAP_PARAMS params;

	if (value_length != sizeof (CK_ECDH_AES_KEY_WRAP_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.ulAESKeyBits);
	p11_rpc_buffer_add_uint64 (buffer, params.kdf);
	p11_rpc_buffer_add_byte_array (buffer, params.pSharedData,
				       params.ulSharedDataLen);
}

bool
p11_rpc_buffer_get_ecdh_aes_key_wrap_mechanism_value (p11_buffer *buffer,
						      size_t *offset,
						      void *value,
						      CK_ULONG *value_length)
{
	CK_ECDH_AES_KEY_WRAP_PARAMS params;
	uint64_t aes_key_bits, kdf;
	const unsigned char *shared_data;
	size_t shared_data_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &aes_key_bits) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &kdf) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &shared_data, &shared_data_len))
		return false;

	if (value) {
		params.ulAESKeyBits = aes_key_bits;
		params.kdf = kdf;
		params.pSharedData = (CK_BYTE_PTR) shared_data;
		params.ulSharedDataLen = shared_data_len;

		memcpy (value, &params, sizeof (CK_ECDH_AES_KEY_WRAP_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_ECDH_AES_KEY_WRAP_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_key_derivation_string_mechanism_value (p11_buffer *buffer,
							  const void *value,
							  CK_ULONG value_length)
{
	CK_KEY_DERIVATION_STRING_DATA params;

	if (value_length != sizeof (CK_KEY_DERIVATION_STRING_DATA)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_byte_array (buffer, params.pData, params.ulLen);
}

bool
p11_rpc_buffer_get_key_derivation_string_mechanism_value (p11_buffer *buffer,
							  size_t *offset,
							  void *value,
							  CK_ULONG *value_length)
{
	CK_KEY_DERIVATION_STRING_DATA params;
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (value) {
		params.pData = (CK_BYTE_PTR) data;
		params.ulLen = len;

		memcpy (value, &params, sizeof (CK_KEY_DERIVATION_STRING_DATA));
	}

	if (value_length)
		*value_length = sizeof (CK_KEY_DERIVATION_STRING_DATA);

	return true;
}

/*
 * CK_AES_CBC_ENCRYPT_DATA_PARAMS, CK_ARIA_CBC_ENCRYPT_DATA_PARAMS,
 * CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS and CK_SEED_CBC_ENCRYPT_DATA_PARAMS
 * are all laid out identically, with a 16 byte IV followed by the data.
 */
void
p11_rpc_buffer_add_cbc_encrypt_data_mechanism_value (p11_buffer *buffer,
						     const void *value,
						     CK_ULONG value_length)
{
	CK_AES_CBC_ENCRYPT_DATA_PARAMS params;

	if (value_length != sizeof (CK_AES_CBC_ENCRYPT_DATA_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_byte_array (buffer, params.iv, sizeof (params.iv));
	p11_rpc_buffer_add_byte_array (buffer, params.pData, params.length);
}

bool
p11_rpc_buffer_get_cbc_encrypt_data_mechanism_value (p11_buffer *buffer,
						     size_t *offset,
						     void *value,
						     CK_ULONG *value_length)
{
	CK_AES_CBC_ENCRYPT_DATA_PARAMS params;
	const unsigned char *iv, *data;
	size_t iv_len, length;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &iv, &iv_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &data, &length))
		return false;

	if (iv_len != sizeof (params.iv))
		return false;

	if (value) {
		memcpy (params.iv, iv, sizeof (params.iv));
		params.pData = (CK_BYTE_PTR) data;
		params.length = length;

		memcpy (value, &params, sizeof (CK_AES_CBC_ENCRYPT_DATA_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_AES_CBC_ENCRYPT_DATA_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_des_cbc_encrypt_data_mechanism_value (p11_buffer *buffer,
							 const void *value,
							 CK_ULONG value_length)
{
	CK_DES_CBC_ENCRYPT_DATA_PARAMS params;

	if (value_length != sizeof (CK_DES_CBC_ENCRYPT_DATA_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_byte_array (buffer, params.iv, sizeof (params.iv));
	p11_rpc_buffer_add_byte_array (buffer, params.pData, params.length);
}

bool
p11_rpc_buffer_get_des_cbc_encrypt_data_mechanism_value (p11_buffer *buffer,
							 size_t *offset,
							 void *value,
							 CK_ULONG *value_length)
{
	CK_DES_CBC_ENCRYPT_DATA_PARAMS params;
	const unsigned char *iv, *data;
	size_t iv_len, length;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &iv, &iv_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &data, &length))
		return false;

	if (iv_len != sizeof (params.iv))
		return false;

	if (value) {
		memcpy (params.iv, iv, sizeof (params.iv));
		params.pData = (CK_BYTE_PTR) data;
		params.length = length;

		memcpy (value, &params, sizeof (CK_DES_CBC_ENCRYPT_DATA_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_DES_CBC_ENCRYPT_DATA_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ecmqv_derive_mechanism_value (p11_buffer *buffer,
						 const void *value,
						 CK_ULONG value_length)
{
	CK_ECMQV_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_ECMQV_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.kdf);
	p11_rpc_buffer_add_byte_array (buffer, params.pSharedData,
				       params.ulSharedDataLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pPublicData,
				       params.ulPublicDataLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulPrivateDataLen);
	p11_rpc_buffer_add_uint64 (buffer, params.hPrivateData);
	p11_rpc_buffer_add_byte_array (buffer, params.pPublicData2,
				       params.ulPublicDataLen2);
	p11_rpc_buffer_add_uint64 (buffer, params.publicKey);
}

bool
p11_rpc_buffer_get_ecmqv_derive_mechanism_value (p11_buffer *buffer,
						 size_t *offset,
						 void *value,
						 CK_ULONG *value_length)
{
	CK_ECMQV_DERIVE_PARAMS params;
	uint64_t kdf, private_data_len, private_data, public_key;
	const unsigned char *shared_data, *public_data, *public_data2;
	size_t shared_data_len, public_data_len, public_data_len2;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &kdf) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &shared_data, &shared_data_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &public_data, &public_data_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &private_data_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &private_data) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &public_data2, &public_data_len2) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &public_key))
		return false;

	if (value) {
		params.kdf = kdf;
		params.pSharedData = (CK_BYTE_PTR) shared_data;
		params.ulSharedDataLen = shared_data_len;
		params.pPublicData = (CK_BYTE_PTR) public_data;
		params.ulPublicDataLen = public_data_len;
		params.ulPrivateDataLen = private_data_len;
		params.hPrivateData = private_data;
		params.pPublicData2 = (CK_BYTE_PTR) public_data2;
		params.ulPublicDataLen2 = public_data_len2;
		params.publicKey = public_key;

		memcpy (value, &params, sizeof (CK_ECMQV_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_ECMQV_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_x9_42_dh1_derive_mechanism_value (p11_buffer *buffer,
						     const void *value,
						     CK_ULONG value_length)
{
	CK_X9_42_DH1_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_X9_42_DH1_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.kdf);
	p11_rpc_buffer_add_byte_array (buffer, params.pOtherInfo,
				       params.ulOtherInfoLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pPublicData,
				       params.ulPublicDataLen);
}

bool
p11_rpc_buffer_get_x9_42_dh1_derive_mechanism_value (p11_buffer *buffer,
						     size_t *offset,
						     void *value,
						     CK_ULONG *value_length)
{
	CK_X9_42_DH1_DERIVE_PARAMS params;
	uint64_t kdf;
	const unsigned char *other_info, *public_data;
	size_t other_info_len, public_data_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &kdf) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &other_info, &other_info_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &public_data, &public_data_len))
		return false;

	if (value) {
		params.kdf = kdf;
		params.pOtherInfo = (CK_BYTE_PTR) other_info;
		params.ulOtherInfoLen = other_info_len;
		params.pPublicData = (CK_BYTE_PTR) public_data;
		params.ulPublicDataLen = public_data_len;

		memcpy (value, &params, sizeof (CK_X9_42_DH1_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_X9_42_DH1_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_x9_42_dh2_derive_mechanism_value (p11_buffer *buffer,
						     const void *value,
						     CK_ULONG value_length)
{
	CK_X9_42_DH2_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_X9_42_DH2_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.kdf);
	p11_rpc_buffer_add_byte_array (buffer, params.pOtherInfo,
				       params.ulOtherInfoLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pPublicData,
				       params.ulPublicDataLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulPrivateDataLen);
	p11_rpc_buffer_add_uint64 (buffer, params.hPrivateData);
	p11_rpc_buffer_add_byte_array (buffer, params.pPublicData2,
				       params.ulPublicDataLen2);
}

bool
p11_rpc_buffer_get_x9_42_dh2_derive_mechanism_value (p11_buffer *buffer,
						     size_t *offset,
						     void *value,
						     CK_ULONG *value_length)
{
	CK_X9_42_DH2_DERIVE_PARAMS params;
	uint64_t kdf, private_data_len, private_data;
	const unsigned char *other_info, *public_data, *public_data2;
	size_t other_info_len, public_data_len, public_data_len2;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &kdf) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &other_info, &other_info_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &public_data, &public_data_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &private_data_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &private_data) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &public_data2, &public_data_len2))
		return false;

	if (value) {
		params.kdf = kdf;
		params.pOtherInfo = (CK_BYTE_PTR) other_info;
		params.ulOtherInfoLen = other_info_len;
		params.pPublicData = (CK_BYTE_PTR) public_data;
		params.ulPublicDataLen = public_data_len;
		params.ulPrivateDataLen = private_data_len;
		params.hPrivateData = private_data;
		params.pPublicData2 = (CK_BYTE_PTR) public_data2;
		params.ulPublicDataLen2 = public_data_len2;

		memcpy (value, &params, sizeof (CK_X9_42_DH2_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_X9_42_DH2_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_x9_42_mqv_derive_mechanism_value (p11_buffer *buffer,
						     const void *value,
						     CK_ULONG value_length)
{
	CK_X9_42_MQV_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_X9_42_MQV_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.kdf);
	p11_rpc_buffer_add_byte_array (buffer, params.pOtherInfo,
				       params.ulOtherInfoLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pPublicData,
				       params.ulPublicDataLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulPrivateDataLen);
	p11_rpc_buffer_add_uint64 (buffer, params.hPrivateData);
	p11_rpc_buffer_add_byte_array (buffer, params.pPublicData2,
				       params.ulPublicDataLen2);
	p11_rpc_buffer_add_uint64 (buffer, params.publicKey);
}

bool
p11_rpc_buffer_get_x9_42_mqv_derive_mechanism_value (p11_buffer *buffer,
						     size_t *offset,
						     void *value,
						     CK_ULONG *value_length)
{
	CK_X9_42_MQV_DERIVE_PARAMS params;
	uint64_t kdf, private_data_len, private_data, public_key;
	const unsigned char *other_info, *public_data, *public_data2;
	size_t other_info_len, public_data_len, public_data_len2;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &kdf) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &other_info, &other_info_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &public_data, &public_data_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &private_data_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &private_data) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &public_data2, &public_data_len2) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &public_key))
		return false;

	if (value) {
		params.kdf = kdf;
		params.pOtherInfo = (CK_BYTE_PTR) other_info;
		params.ulOtherInfoLen = other_info_len;
		params.pPublicData = (CK_BYTE_PTR) public_data;
		params.ulPublicDataLen = public_data_len;
		params.ulPrivateDataLen = private_data_len;
		params.hPrivateData = private_data;
		params.pPublicData2 = (CK_BYTE_PTR) public_data2;
		params.ulPublicDataLen2 = public_data_len2;
		params.publicKey = public_key;

		memcpy (value, &params, sizeof (CK_X9_42_MQV_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_X9_42_MQV_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_kea_derive_mechanism_value (p11_buffer *buffer,
					       const void *value,
					       CK_ULONG value_length)
{
	CK_KEA_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_KEA_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_byte (buffer, params.isSender ? 1 : 0);
	p11_rpc_buffer_add_uint64 (buffer, params.ulRandomLen);
	p11_rpc_buffer_add_byte_array (buffer, params.RandomA,
				       params.ulRandomLen);
	p11_rpc_buffer_add_byte_array (buffer, params.RandomB,
				       params.ulRandomLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pPublicData,
				       params.ulPublicDataLen);
}

bool
p11_rpc_buffer_get_kea_derive_mechanism_value (p11_buffer *buffer,
					       size_t *offset,
					       void *value,
					       CK_ULONG *value_length)
{
	CK_KEA_DERIVE_PARAMS params;
	uint64_t random_len;
	unsigned char is_sender;
	const unsigned char *random_a, *random_b, *public_data;
	size_t random_a_len, random_b_len, public_data_len;

	if (!p11_rpc_buffer_get_byte (buffer, offset, &is_sender) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &random_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &random_a, &random_a_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &random_b, &random_b_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &public_data, &public_data_len))
		return false;

	/* Both random values are ulRandomLen bytes long */
	if ((random_a != NULL && random_a_len != random_len) ||
	    (random_b != NULL && random_b_len != random_len))
		return false;

	if (value) {
		params.isSender = is_sender ? CK_TRUE : CK_FALSE;
		params.ulRandomLen = random_len;
		params.RandomA = (CK_BYTE_PTR) random_a;
		params.RandomB = (CK_BYTE_PTR) random_b;
		params.pPublicData = (CK_BYTE_PTR) public_data;
		params.ulPublicDataLen = public_data_len;

		memcpy (value, &params, sizeof (CK_KEA_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_KEA_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_aes_ccm_mechanism_value (p11_buffer *buffer,
					    const void *value,
					    CK_ULONG value_length)
{
	CK_CCM_PARAMS params;

	if (value_length != sizeof (CK_CCM_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.ulDataLen);
	p11_rpc_buffer_add_byte_array (buffer, params.nonce, params.ulNonceLen);
	p11_rpc_buffer_add_byte_array (buffer, params.aad, params.ulAADLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulMACLen);
}

bool
p11_rpc_buffer_get_aes_ccm_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	CK_CCM_PARAMS params;
	uint64_t data_len, mac_len;
	const unsigned char *nonce, *aad;
	size_t nonce_len, aad_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &data_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &nonce, &nonce_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &aad, &aad_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &mac_len))
		return false;

	if (value) {
		params.ulDataLen = data_len;
		params.nonce = (CK_BYTE_PTR) nonce;
		params.ulNonceLen = nonce_len;
		params.aad = (CK_BYTE_PTR) aad;
		params.ulAADLen = aad_len;
		params.ulMACLen = mac_len;

		memcpy (value, &params, sizeof (CK_CCM_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_CCM_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_chacha20_mechanism_value (p11_buffer *buffer,
					     const void *value,
					     CK_ULONG value_length)
{
	CK_CHACHA20_PARAMS params;
	size_t counter_len, nonce_len;

	if (value_length != sizeof (CK_CHACHA20_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	if (!bits_to_bytes (params.blockCounterBits, &counter_len) ||
	    !bits_to_bytes (params.ulNonceBits, &nonce_len)) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.blockCounterBits);
	p11_rpc_buffer_add_byte_array (buffer, params.pBlockCounter, counter_len);
	p11_rpc_buffer_add_uint64 (buffer, params.ulNonceBits);
	p11_rpc_buffer_add_byte_array (buffer, params.pNonce, nonce_len);
}

bool
p11_rpc_buffer_get_chacha20_mechanism_value (p11_buffer *buffer,
					     size_t *offset,
					     void *value,
					     CK_ULONG *value_length)
{
	CK_CHACHA20_PARAMS params;
	uint64_t block_counter_bits, nonce_bits;
	const unsigned char *block_counter, *nonce;
	size_t block_counter_len, nonce_len, expected;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &block_counter_bits) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &block_counter, &block_counter_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &nonce_bits) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &nonce, &nonce_len))
		return false;

	if (block_counter != NULL &&
	    (!bits_to_bytes (block_counter_bits, &expected) ||
	     block_counter_len != expected))
		return false;
	if (nonce != NULL &&
	    (!bits_to_bytes (nonce_bits, &expected) || nonce_len != expected))
		return false;

	if (value) {
		params.pBlockCounter = (CK_BYTE_PTR) block_counter;
		params.blockCounterBits = block_counter_bits;
		params.pNonce = (CK_BYTE_PTR) nonce;
		params.ulNonceBits = nonce_bits;

		memcpy (value, &params, sizeof (CK_CHACHA20_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_CHACHA20_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_salsa20_mechanism_value (p11_buffer *buffer,
					    const void *value,
					    CK_ULONG value_length)
{
	CK_SALSA20_PARAMS params;
	size_t nonce_len;

	if (value_length != sizeof (CK_SALSA20_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	if (!bits_to_bytes (params.ulNonceBits, &nonce_len)) {
		p11_buffer_fail (buffer);
		return;
	}

	/* The Salsa20 block counter is always 64 bits wide */
	p11_rpc_buffer_add_byte_array (buffer, params.pBlockCounter, 8);
	p11_rpc_buffer_add_uint64 (buffer, params.ulNonceBits);
	p11_rpc_buffer_add_byte_array (buffer, params.pNonce, nonce_len);
}

bool
p11_rpc_buffer_get_salsa20_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	CK_SALSA20_PARAMS params;
	uint64_t nonce_bits;
	const unsigned char *block_counter, *nonce;
	size_t block_counter_len, nonce_len, expected;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset,
					    &block_counter, &block_counter_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &nonce_bits) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &nonce, &nonce_len))
		return false;

	if (block_counter != NULL && block_counter_len != 8)
		return false;
	if (nonce != NULL &&
	    (!bits_to_bytes (nonce_bits, &expected) || nonce_len != expected))
		return false;

	if (value) {
		params.pBlockCounter = (CK_BYTE_PTR) block_counter;
		params.pNonce = (CK_BYTE_PTR) nonce;
		params.ulNonceBits = nonce_bits;

		memcpy (value, &params, sizeof (CK_SALSA20_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_SALSA20_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_poly1305_mechanism_value (p11_buffer *buffer,
					     const void *value,
					     CK_ULONG value_length)
{
	CK_SALSA20_CHACHA20_POLY1305_PARAMS params;
	size_t nonce_len;

	if (value_length != sizeof (CK_SALSA20_CHACHA20_POLY1305_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	if (!bits_to_bytes (params.ulNonceBits, &nonce_len)) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.ulNonceBits);
	p11_rpc_buffer_add_byte_array (buffer, params.pNonce, nonce_len);
	p11_rpc_buffer_add_byte_array (buffer, params.pAAD, params.ulAADLen);
}

bool
p11_rpc_buffer_get_poly1305_mechanism_value (p11_buffer *buffer,
					     size_t *offset,
					     void *value,
					     CK_ULONG *value_length)
{
	CK_SALSA20_CHACHA20_POLY1305_PARAMS params;
	uint64_t nonce_bits;
	const unsigned char *nonce, *aad;
	size_t nonce_len, aad_len, expected;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &nonce_bits) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &nonce, &nonce_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &aad, &aad_len))
		return false;

	if (nonce != NULL &&
	    (!bits_to_bytes (nonce_bits, &expected) || nonce_len != expected))
		return false;

	if (value) {
		params.pNonce = (CK_BYTE_PTR) nonce;
		params.ulNonceBits = nonce_bits;
		params.pAAD = (CK_BYTE_PTR) aad;
		params.ulAADLen = aad_len;

		memcpy (value, &params,
			sizeof (CK_SALSA20_CHACHA20_POLY1305_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_SALSA20_CHACHA20_POLY1305_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_gostr3410_derive_mechanism_value (p11_buffer *buffer,
						     const void *value,
						     CK_ULONG value_length)
{
	CK_GOSTR3410_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_GOSTR3410_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.kdf);
	p11_rpc_buffer_add_byte_array (buffer, params.pPublicData,
				       params.ulPublicDataLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pUKM, params.ulUKMLen);
}

bool
p11_rpc_buffer_get_gostr3410_derive_mechanism_value (p11_buffer *buffer,
						     size_t *offset,
						     void *value,
						     CK_ULONG *value_length)
{
	CK_GOSTR3410_DERIVE_PARAMS params;
	uint64_t kdf;
	const unsigned char *public_data, *ukm;
	size_t public_data_len, ukm_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &kdf) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &public_data, &public_data_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &ukm, &ukm_len))
		return false;

	if (value) {
		params.kdf = kdf;
		params.pPublicData = (CK_BYTE_PTR) public_data;
		params.ulPublicDataLen = public_data_len;
		params.pUKM = (CK_BYTE_PTR) ukm;
		params.ulUKMLen = ukm_len;

		memcpy (value, &params, sizeof (CK_GOSTR3410_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_GOSTR3410_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_gostr3410_key_wrap_mechanism_value (p11_buffer *buffer,
						       const void *value,
						       CK_ULONG value_length)
{
	CK_GOSTR3410_KEY_WRAP_PARAMS params;

	if (value_length != sizeof (CK_GOSTR3410_KEY_WRAP_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_byte_array (buffer, params.pWrapOID,
				       params.ulWrapOIDLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pUKM, params.ulUKMLen);
	p11_rpc_buffer_add_uint64 (buffer, params.hKey);
}

bool
p11_rpc_buffer_get_gostr3410_key_wrap_mechanism_value (p11_buffer *buffer,
						       size_t *offset,
						       void *value,
						       CK_ULONG *value_length)
{
	CK_GOSTR3410_KEY_WRAP_PARAMS params;
	uint64_t key;
	const unsigned char *wrap_oid, *ukm;
	size_t wrap_oid_len, ukm_len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &wrap_oid, &wrap_oid_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &ukm, &ukm_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &key))
		return false;

	if (value) {
		params.pWrapOID = (CK_BYTE_PTR) wrap_oid;
		params.ulWrapOIDLen = wrap_oid_len;
		params.pUKM = (CK_BYTE_PTR) ukm;
		params.ulUKMLen = ukm_len;
		params.hKey = key;

		memcpy (value, &params, sizeof (CK_GOSTR3410_KEY_WRAP_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_GOSTR3410_KEY_WRAP_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_hkdf_mechanism_value (p11_buffer *buffer,
					 const void *value,
					 CK_ULONG value_length)
{
	CK_HKDF_PARAMS params;

	if (value_length != sizeof (CK_HKDF_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_byte (buffer, params.bExtract ? 1 : 0);
	p11_rpc_buffer_add_byte (buffer, params.bExpand ? 1 : 0);
	p11_rpc_buffer_add_uint64 (buffer, params.prfHashMechanism);
	p11_rpc_buffer_add_uint64 (buffer, params.ulSaltType);
	p11_rpc_buffer_add_byte_array (buffer, params.pSalt, params.ulSaltLen);
	p11_rpc_buffer_add_uint64 (buffer, params.hSaltKey);
	p11_rpc_buffer_add_byte_array (buffer, params.pInfo, params.ulInfoLen);
}

bool
p11_rpc_buffer_get_hkdf_mechanism_value (p11_buffer *buffer,
					 size_t *offset,
					 void *value,
					 CK_ULONG *value_length)
{
	CK_HKDF_PARAMS params;
	uint64_t prf_hash_mechanism, salt_type, salt_key;
	unsigned char extract, expand;
	const unsigned char *salt, *info;
	size_t salt_len, info_len;

	if (!p11_rpc_buffer_get_byte (buffer, offset, &extract) ||
	    !p11_rpc_buffer_get_byte (buffer, offset, &expand) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &prf_hash_mechanism) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &salt_type) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &salt, &salt_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &salt_key) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &info, &info_len))
		return false;

	if (value) {
		params.bExtract = extract ? CK_TRUE : CK_FALSE;
		params.bExpand = expand ? CK_TRUE : CK_FALSE;
		params.prfHashMechanism = prf_hash_mechanism;
		params.ulSaltType = salt_type;
		params.pSalt = (CK_BYTE_PTR) salt;
		params.ulSaltLen = salt_len;
		params.hSaltKey = salt_key;
		params.pInfo = (CK_BYTE_PTR) info;
		params.ulInfoLen = info_len;

		memcpy (value, &params, sizeof (CK_HKDF_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_HKDF_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ike_prf_derive_mechanism_value (p11_buffer *buffer,
						   const void *value,
						   CK_ULONG value_length)
{
	CK_IKE_PRF_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_IKE_PRF_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.prfMechanism);
	p11_rpc_buffer_add_byte (buffer, params.bDataAsKey ? 1 : 0);
	p11_rpc_buffer_add_byte (buffer, params.bRekey ? 1 : 0);
	p11_rpc_buffer_add_byte_array (buffer, params.pNi, params.ulNiLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pNr, params.ulNrLen);
	p11_rpc_buffer_add_uint64 (buffer, params.hNewKey);
}

bool
p11_rpc_buffer_get_ike_prf_derive_mechanism_value (p11_buffer *buffer,
						   size_t *offset,
						   void *value,
						   CK_ULONG *value_length)
{
	CK_IKE_PRF_DERIVE_PARAMS params;
	uint64_t prf_mechanism, new_key;
	unsigned char data_as_key, rekey;
	const unsigned char *ni, *nr;
	size_t ni_len, nr_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &prf_mechanism) ||
	    !p11_rpc_buffer_get_byte (buffer, offset, &data_as_key) ||
	    !p11_rpc_buffer_get_byte (buffer, offset, &rekey) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &ni, &ni_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &nr, &nr_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &new_key))
		return false;

	if (value) {
		params.prfMechanism = prf_mechanism;
		params.bDataAsKey = data_as_key ? CK_TRUE : CK_FALSE;
		params.bRekey = rekey ? CK_TRUE : CK_FALSE;
		params.pNi = (CK_BYTE_PTR) ni;
		params.ulNiLen = ni_len;
		params.pNr = (CK_BYTE_PTR) nr;
		params.ulNrLen = nr_len;
		params.hNewKey = new_key;

		memcpy (value, &params, sizeof (CK_IKE_PRF_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_IKE_PRF_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ike1_prf_derive_mechanism_value (p11_buffer *buffer,
						    const void *value,
						    CK_ULONG value_length)
{
	CK_IKE1_PRF_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_IKE1_PRF_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.prfMechanism);
	p11_rpc_buffer_add_byte (buffer, params.bHasPrevKey ? 1 : 0);
	p11_rpc_buffer_add_uint64 (buffer, params.hKeygxy);
	p11_rpc_buffer_add_uint64 (buffer, params.hPrevKey);
	p11_rpc_buffer_add_byte_array (buffer, params.pCKYi, params.ulCKYiLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pCKYr, params.ulCKYrLen);
	p11_rpc_buffer_add_byte (buffer, params.keyNumber);
}

bool
p11_rpc_buffer_get_ike1_prf_derive_mechanism_value (p11_buffer *buffer,
						    size_t *offset,
						    void *value,
						    CK_ULONG *value_length)
{
	CK_IKE1_PRF_DERIVE_PARAMS params;
	uint64_t prf_mechanism, keygxy, prev_key;
	unsigned char has_prev_key, key_number;
	const unsigned char *ck_yi, *ck_yr;
	size_t ck_yi_len, ck_yr_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &prf_mechanism) ||
	    !p11_rpc_buffer_get_byte (buffer, offset, &has_prev_key) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &keygxy) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &prev_key) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &ck_yi, &ck_yi_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &ck_yr, &ck_yr_len) ||
	    !p11_rpc_buffer_get_byte (buffer, offset, &key_number))
		return false;

	if (value) {
		params.prfMechanism = prf_mechanism;
		params.bHasPrevKey = has_prev_key ? CK_TRUE : CK_FALSE;
		params.hKeygxy = keygxy;
		params.hPrevKey = prev_key;
		params.pCKYi = (CK_BYTE_PTR) ck_yi;
		params.ulCKYiLen = ck_yi_len;
		params.pCKYr = (CK_BYTE_PTR) ck_yr;
		params.ulCKYrLen = ck_yr_len;
		params.keyNumber = key_number;

		memcpy (value, &params, sizeof (CK_IKE1_PRF_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_IKE1_PRF_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ike1_extended_derive_mechanism_value (p11_buffer *buffer,
							 const void *value,
							 CK_ULONG value_length)
{
	CK_IKE1_EXTENDED_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_IKE1_EXTENDED_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.prfMechanism);
	p11_rpc_buffer_add_byte (buffer, params.bHasKeygxy ? 1 : 0);
	p11_rpc_buffer_add_uint64 (buffer, params.hKeygxy);
	p11_rpc_buffer_add_byte_array (buffer, params.pExtraData,
				       params.ulExtraDataLen);
}

bool
p11_rpc_buffer_get_ike1_extended_derive_mechanism_value (p11_buffer *buffer,
							 size_t *offset,
							 void *value,
							 CK_ULONG *value_length)
{
	CK_IKE1_EXTENDED_DERIVE_PARAMS params;
	uint64_t prf_mechanism, keygxy;
	unsigned char has_key_gxy;
	const unsigned char *extra_data;
	size_t extra_data_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &prf_mechanism) ||
	    !p11_rpc_buffer_get_byte (buffer, offset, &has_key_gxy) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &keygxy) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &extra_data, &extra_data_len))
		return false;

	if (value) {
		params.prfMechanism = prf_mechanism;
		params.bHasKeygxy = has_key_gxy ? CK_TRUE : CK_FALSE;
		params.hKeygxy = keygxy;
		params.pExtraData = (CK_BYTE_PTR) extra_data;
		params.ulExtraDataLen = extra_data_len;

		memcpy (value, &params,
			sizeof (CK_IKE1_EXTENDED_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_IKE1_EXTENDED_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ike2_prf_plus_derive_mechanism_value (p11_buffer *buffer,
							 const void *value,
							 CK_ULONG value_length)
{
	CK_IKE2_PRF_PLUS_DERIVE_PARAMS params;

	if (value_length != sizeof (CK_IKE2_PRF_PLUS_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.prfMechanism);
	p11_rpc_buffer_add_byte (buffer, params.bHasSeedKey ? 1 : 0);
	p11_rpc_buffer_add_uint64 (buffer, params.hSeedKey);
	p11_rpc_buffer_add_byte_array (buffer, params.pSeedData,
				       params.ulSeedDataLen);
}

bool
p11_rpc_buffer_get_ike2_prf_plus_derive_mechanism_value (p11_buffer *buffer,
							 size_t *offset,
							 void *value,
							 CK_ULONG *value_length)
{
	CK_IKE2_PRF_PLUS_DERIVE_PARAMS params;
	uint64_t prf_mechanism, seed_key;
	unsigned char has_seed_key;
	const unsigned char *seed_data;
	size_t seed_data_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &prf_mechanism) ||
	    !p11_rpc_buffer_get_byte (buffer, offset, &has_seed_key) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &seed_key) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &seed_data, &seed_data_len))
		return false;

	if (value) {
		params.prfMechanism = prf_mechanism;
		params.bHasSeedKey = has_seed_key ? CK_TRUE : CK_FALSE;
		params.hSeedKey = seed_key;
		params.pSeedData = (CK_BYTE_PTR) seed_data;
		params.ulSeedDataLen = seed_data_len;

		memcpy (value, &params,
			sizeof (CK_IKE2_PRF_PLUS_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_IKE2_PRF_PLUS_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_key_wrap_set_oaep_mechanism_value (p11_buffer *buffer,
						      const void *value,
						      CK_ULONG value_length)
{
	CK_KEY_WRAP_SET_OAEP_PARAMS params;

	if (value_length != sizeof (CK_KEY_WRAP_SET_OAEP_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_byte (buffer, params.bBC);
	p11_rpc_buffer_add_byte_array (buffer, params.pX, params.ulXLen);
}

bool
p11_rpc_buffer_get_key_wrap_set_oaep_mechanism_value (p11_buffer *buffer,
						      size_t *offset,
						      void *value,
						      CK_ULONG *value_length)
{
	CK_KEY_WRAP_SET_OAEP_PARAMS params;
	unsigned char bc;
	const unsigned char *x;
	size_t x_len;

	if (!p11_rpc_buffer_get_byte (buffer, offset, &bc) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &x, &x_len))
		return false;

	if (value) {
		params.bBC = bc;
		params.pX = (CK_BYTE_PTR) x;
		params.ulXLen = x_len;

		memcpy (value, &params, sizeof (CK_KEY_WRAP_SET_OAEP_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_KEY_WRAP_SET_OAEP_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_skipjack_private_wrap_mechanism_value (p11_buffer *buffer,
							  const void *value,
							  CK_ULONG value_length)
{
	CK_SKIPJACK_PRIVATE_WRAP_PARAMS params;

	if (value_length != sizeof (CK_SKIPJACK_PRIVATE_WRAP_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_byte_array (buffer, params.pPassword,
				       params.ulPasswordLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pPublicData,
				       params.ulPublicDataLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pRandomA,
				       params.ulRandomLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pPrimeP,
				       params.ulPAndGLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pBaseG,
				       params.ulPAndGLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pSubprimeQ,
				       params.ulQLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulPAndGLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulQLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulRandomLen);
}

bool
p11_rpc_buffer_get_skipjack_private_wrap_mechanism_value (p11_buffer *buffer,
							  size_t *offset,
							  void *value,
							  CK_ULONG *value_length)
{
	CK_SKIPJACK_PRIVATE_WRAP_PARAMS params;
	uint64_t p_and_g_len, q_len, random_len;
	const unsigned char *password, *public_data, *random_a;
	const unsigned char *prime_p, *base_g, *subprime_q;
	size_t password_len, public_data_len, random_a_len;
	size_t prime_p_len, base_g_len, subprime_q_len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset,
					    &password, &password_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &public_data, &public_data_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &random_a, &random_a_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &prime_p, &prime_p_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &base_g, &base_g_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &subprime_q, &subprime_q_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &p_and_g_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &q_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &random_len))
		return false;

	/*
	 * ulPAndGLen, ulQLen and ulRandomLen size buffers that are sent
	 * separately, so they have to agree with what arrived.
	 */
	if ((random_a != NULL && random_a_len != random_len) ||
	    (prime_p != NULL && prime_p_len != p_and_g_len) ||
	    (base_g != NULL && base_g_len != p_and_g_len) ||
	    (subprime_q != NULL && subprime_q_len != q_len))
		return false;

	if (value) {
		params.pPassword = (CK_BYTE_PTR) password;
		params.ulPasswordLen = password_len;
		params.pPublicData = (CK_BYTE_PTR) public_data;
		params.ulPublicDataLen = public_data_len;
		params.pRandomA = (CK_BYTE_PTR) random_a;
		params.pPrimeP = (CK_BYTE_PTR) prime_p;
		params.pBaseG = (CK_BYTE_PTR) base_g;
		params.pSubprimeQ = (CK_BYTE_PTR) subprime_q;
		params.ulPAndGLen = p_and_g_len;
		params.ulQLen = q_len;
		params.ulRandomLen = random_len;

		memcpy (value, &params,
			sizeof (CK_SKIPJACK_PRIVATE_WRAP_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_SKIPJACK_PRIVATE_WRAP_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_skipjack_relayx_mechanism_value (p11_buffer *buffer,
						    const void *value,
						    CK_ULONG value_length)
{
	CK_SKIPJACK_RELAYX_PARAMS params;

	if (value_length != sizeof (CK_SKIPJACK_RELAYX_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_byte_array (buffer, params.pOldWrappedX,
				       params.ulOldWrappedXLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pOldPassword,
				       params.ulOldPasswordLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pOldPublicData,
				       params.ulOldPublicDataLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pOldRandomA,
				       params.ulOldRandomLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pNewPassword,
				       params.ulNewPasswordLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pNewPublicData,
				       params.ulNewPublicDataLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pNewRandomA,
				       params.ulNewRandomLen);
}

bool
p11_rpc_buffer_get_skipjack_relayx_mechanism_value (p11_buffer *buffer,
						    size_t *offset,
						    void *value,
						    CK_ULONG *value_length)
{
	CK_SKIPJACK_RELAYX_PARAMS params;
	const unsigned char *old_wrapped_x, *old_password, *old_public_data;
	const unsigned char *old_random_a, *new_password;
	const unsigned char *new_public_data, *new_random_a;
	size_t old_wrapped_x_len, old_password_len, old_public_data_len;
	size_t old_random_len, new_password_len;
	size_t new_public_data_len, new_random_len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset,
					    &old_wrapped_x, &old_wrapped_x_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &old_password, &old_password_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &old_public_data, &old_public_data_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &old_random_a, &old_random_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &new_password, &new_password_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &new_public_data, &new_public_data_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &new_random_a, &new_random_len))
		return false;

	if (value) {
		params.pOldWrappedX = (CK_BYTE_PTR) old_wrapped_x;
		params.ulOldWrappedXLen = old_wrapped_x_len;
		params.pOldPassword = (CK_BYTE_PTR) old_password;
		params.ulOldPasswordLen = old_password_len;
		params.pOldPublicData = (CK_BYTE_PTR) old_public_data;
		params.ulOldPublicDataLen = old_public_data_len;
		params.pOldRandomA = (CK_BYTE_PTR) old_random_a;
		params.ulOldRandomLen = old_random_len;
		params.pNewPassword = (CK_BYTE_PTR) new_password;
		params.ulNewPasswordLen = new_password_len;
		params.pNewPublicData = (CK_BYTE_PTR) new_public_data;
		params.ulNewPublicDataLen = new_public_data_len;
		params.pNewRandomA = (CK_BYTE_PTR) new_random_a;
		params.ulNewRandomLen = new_random_len;

		memcpy (value, &params, sizeof (CK_SKIPJACK_RELAYX_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_SKIPJACK_RELAYX_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_pkcs5_pbkd2_mechanism_value (p11_buffer *buffer,
						const void *value,
						CK_ULONG value_length)
{
	CK_PKCS5_PBKD2_PARAMS2 params;

	if (value_length != sizeof (CK_PKCS5_PBKD2_PARAMS2)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.saltSource);
	p11_rpc_buffer_add_byte_array (buffer, params.pSaltSourceData,
				       params.ulSaltSourceDataLen);
	p11_rpc_buffer_add_uint64 (buffer, params.iterations);
	p11_rpc_buffer_add_uint64 (buffer, params.prf);
	p11_rpc_buffer_add_byte_array (buffer, params.pPrfData,
				       params.ulPrfDataLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pPassword,
				       params.ulPasswordLen);
}

bool
p11_rpc_buffer_get_pkcs5_pbkd2_mechanism_value (p11_buffer *buffer,
						size_t *offset,
						void *value,
						CK_ULONG *value_length)
{
	CK_PKCS5_PBKD2_PARAMS2 params;
	uint64_t salt_source, iterations, prf;
	const unsigned char *salt_source_data, *prf_data, *password;
	size_t salt_source_data_len, prf_data_len, password_len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &salt_source) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &salt_source_data, &salt_source_data_len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &iterations) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &prf) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &prf_data, &prf_data_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &password, &password_len))
		return false;

	if (value) {
		params.saltSource = salt_source;
		params.pSaltSourceData = (void *) salt_source_data;
		params.ulSaltSourceDataLen = salt_source_data_len;
		params.iterations = iterations;
		params.prf = prf;
		params.pPrfData = (void *) prf_data;
		params.ulPrfDataLen = prf_data_len;
		params.pPassword = (CK_BYTE_PTR) password;
		params.ulPasswordLen = password_len;

		memcpy (value, &params, sizeof (CK_PKCS5_PBKD2_PARAMS2));
	}

	if (value_length)
		*value_length = sizeof (CK_PKCS5_PBKD2_PARAMS2);

	return true;
}

void
p11_rpc_buffer_add_tls_mac_mechanism_value (p11_buffer *buffer,
					    const void *value,
					    CK_ULONG value_length)
{
	CK_TLS_MAC_PARAMS params;

	if (value_length != sizeof (CK_TLS_MAC_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.prfHashMechanism);
	p11_rpc_buffer_add_uint64 (buffer, params.ulMacLength);
	p11_rpc_buffer_add_uint64 (buffer, params.ulServerOrClient);
}

bool
p11_rpc_buffer_get_tls_mac_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	CK_TLS_MAC_PARAMS params;
	uint64_t prf_hash_mechanism, mac_length, server_or_client;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &prf_hash_mechanism) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &mac_length) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &server_or_client))
		return false;

	if (value) {
		params.prfHashMechanism = prf_hash_mechanism;
		params.ulMacLength = mac_length;
		params.ulServerOrClient = server_or_client;

		memcpy (value, &params, sizeof (CK_TLS_MAC_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_TLS_MAC_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_tls_kdf_mechanism_value (p11_buffer *buffer,
					    const void *value,
					    CK_ULONG value_length)
{
	CK_TLS_KDF_PARAMS params;

	if (value_length != sizeof (CK_TLS_KDF_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	p11_rpc_buffer_add_uint64 (buffer, params.prfMechanism);
	p11_rpc_buffer_add_byte_array (buffer, params.pLabel,
				       params.ulLabelLength);
	p11_rpc_buffer_add_byte_array (buffer, params.RandomInfo.pClientRandom,
				       params.RandomInfo.ulClientRandomLen);
	p11_rpc_buffer_add_byte_array (buffer, params.RandomInfo.pServerRandom,
				       params.RandomInfo.ulServerRandomLen);
	p11_rpc_buffer_add_byte_array (buffer, params.pContextData,
				       params.ulContextDataLength);
}

bool
p11_rpc_buffer_get_tls_kdf_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	CK_TLS_KDF_PARAMS params;
	uint64_t prf_mechanism;
	const unsigned char *label, *client_random, *server_random;
	const unsigned char *context_data;
	size_t label_length, client_random_len, server_random_len;
	size_t context_data_length;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &prf_mechanism) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &label, &label_length) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &client_random, &client_random_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &server_random, &server_random_len) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset,
					    &context_data, &context_data_length))
		return false;

	if (value) {
		params.prfMechanism = prf_mechanism;
		params.pLabel = (CK_BYTE_PTR) label;
		params.ulLabelLength = label_length;
		params.RandomInfo.pClientRandom = (CK_BYTE_PTR) client_random;
		params.RandomInfo.ulClientRandomLen = client_random_len;
		params.RandomInfo.pServerRandom = (CK_BYTE_PTR) server_random;
		params.RandomInfo.ulServerRandomLen = server_random_len;
		params.pContextData = (CK_BYTE_PTR) context_data;
		params.ulContextDataLength = context_data_length;

		memcpy (value, &params, sizeof (CK_TLS_KDF_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_TLS_KDF_PARAMS);

	return true;
}

static p11_rpc_mechanism_serializer p11_rpc_mech_param_update_serializers[] = {
	{ CKM_IBM_BTC_DERIVE, p11_rpc_buffer_add_ibm_btc_derive_mech_param_update, p11_rpc_buffer_get_ibm_btc_derive_mech_param_update },
	{ CKM_IBM_KYBER, p11_rpc_buffer_add_ibm_kyber_mech_param_update, p11_rpc_buffer_get_ibm_kyber_mech_param_update },
};

static p11_rpc_mechanism_serializer p11_rpc_mechanism_serializers[] = {
	{ CKM_IBM_ECDSA_OTHER, p11_rpc_buffer_add_ibm_ecdsa_other_mechanism_value, p11_rpc_buffer_get_ibm_ecdsa_other_mechanism_value },
	{ CKM_IBM_BTC_DERIVE, p11_rpc_buffer_add_ibm_btc_derive_mechanism_value, p11_rpc_buffer_get_ibm_btc_derive_mechanism_value },
	{ CKM_IBM_KYBER, p11_rpc_buffer_add_ibm_kyber_mechanism_value, p11_rpc_buffer_get_ibm_kyber_mechanism_value },
	{ CKM_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA1_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA224_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA256_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA384_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA512_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_RSA_PKCS_OAEP, p11_rpc_buffer_add_rsa_pkcs_oaep_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_oaep_mechanism_value },
	{ CKM_ECDH1_DERIVE, p11_rpc_buffer_add_ecdh1_derive_mechanism_value, p11_rpc_buffer_get_ecdh1_derive_mechanism_value },
	{ CKM_EDDSA, p11_rpc_buffer_add_eddsa_mechanism_value, p11_rpc_buffer_get_eddsa_mechanism_value },
	{ CKM_ML_DSA, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_ML_DSA, p11_rpc_buffer_add_hash_sign_additional_context_mechanism_value, p11_rpc_buffer_get_hash_sign_additional_context_mechanism_value },
	{ CKM_HASH_ML_DSA_SHA224, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_ML_DSA_SHA256, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_ML_DSA_SHA384, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_ML_DSA_SHA512, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_ML_DSA_SHA3_224, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_ML_DSA_SHA3_256, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_ML_DSA_SHA3_384, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_ML_DSA_SHA3_512, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_ML_DSA_SHAKE128, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_ML_DSA_SHAKE256, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_SLH_DSA, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_SLH_DSA, p11_rpc_buffer_add_hash_sign_additional_context_mechanism_value, p11_rpc_buffer_get_hash_sign_additional_context_mechanism_value },
	{ CKM_HASH_SLH_DSA_SHA224, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_SLH_DSA_SHA256, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_SLH_DSA_SHA384, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_SLH_DSA_SHA512, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_SLH_DSA_SHA3_224, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_SLH_DSA_SHA3_256, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_SLH_DSA_SHA3_384, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_SLH_DSA_SHA3_512, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_SLH_DSA_SHAKE128, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_HASH_SLH_DSA_SHAKE256, p11_rpc_buffer_add_sign_additional_context_mechanism_value, p11_rpc_buffer_get_sign_additional_context_mechanism_value },
	{ CKM_IBM_ATTRIBUTEBOUND_WRAP, p11_rpc_buffer_add_ibm_attrbound_wrap_mechanism_value, p11_rpc_buffer_get_ibm_attrbound_wrap_mechanism_value },
	{ CKM_IBM_EC_X25519, p11_rpc_buffer_add_ecdh1_derive_mechanism_value, p11_rpc_buffer_get_ecdh1_derive_mechanism_value },
	{ CKM_IBM_EC_X448, p11_rpc_buffer_add_ecdh1_derive_mechanism_value, p11_rpc_buffer_get_ecdh1_derive_mechanism_value },
	{ CKM_AES_CBC, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CBC_PAD, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_OFB, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CFB1, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CFB8, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CFB64, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CFB128, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CTS, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CTR, p11_rpc_buffer_add_aes_ctr_mechanism_value, p11_rpc_buffer_get_aes_ctr_mechanism_value },
	{ CKM_AES_GCM, p11_rpc_buffer_add_aes_gcm_mechanism_value, p11_rpc_buffer_get_aes_gcm_mechanism_value },
	{ CKM_DES_CBC, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES_CBC_PAD, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES3_CBC, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES3_CBC_PAD, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES_CFB8, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES_CFB64, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES_OFB64, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_SHA_1_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA224_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA256_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA384_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA512_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA512_224_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA512_256_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_AES_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_AES_CMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_DES3_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_DES3_CMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_DH_PKCS_DERIVE, p11_rpc_buffer_add_dh_pkcs_derive_mechanism_value, p11_rpc_buffer_get_dh_pkcs_derive_mechanism_value },

	/* RSA */
	{ CKM_SHA3_224_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA3_256_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA3_384_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA3_512_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },

	/* DSA domain parameter generation */
	{ CKM_DSA_PROBABILISTIC_PARAMETER_GEN, p11_rpc_buffer_add_dsa_parameter_gen_mechanism_value, p11_rpc_buffer_get_dsa_parameter_gen_mechanism_value },
	{ CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN, p11_rpc_buffer_add_dsa_parameter_gen_mechanism_value, p11_rpc_buffer_get_dsa_parameter_gen_mechanism_value },
	{ CKM_DSA_FIPS_G_GEN, p11_rpc_buffer_add_dsa_parameter_gen_mechanism_value, p11_rpc_buffer_get_dsa_parameter_gen_mechanism_value },

	/* Elliptic curve */
	{ CKM_ECDH1_COFACTOR_DERIVE, p11_rpc_buffer_add_ecdh1_derive_mechanism_value, p11_rpc_buffer_get_ecdh1_derive_mechanism_value },
	{ CKM_ECMQV_DERIVE, p11_rpc_buffer_add_ecmqv_derive_mechanism_value, p11_rpc_buffer_get_ecmqv_derive_mechanism_value },
	{ CKM_ECDH_AES_KEY_WRAP, p11_rpc_buffer_add_ecdh_aes_key_wrap_mechanism_value, p11_rpc_buffer_get_ecdh_aes_key_wrap_mechanism_value },
	{ CKM_ECDH_COF_AES_KEY_WRAP, p11_rpc_buffer_add_ecdh_aes_key_wrap_mechanism_value, p11_rpc_buffer_get_ecdh_aes_key_wrap_mechanism_value },
	{ CKM_ECDH_X_AES_KEY_WRAP, p11_rpc_buffer_add_ecdh_aes_key_wrap_mechanism_value, p11_rpc_buffer_get_ecdh_aes_key_wrap_mechanism_value },
	{ CKM_XEDDSA, p11_rpc_buffer_add_xeddsa_mechanism_value, p11_rpc_buffer_get_xeddsa_mechanism_value },

	/* X9.42 Diffie-Hellman */
	{ CKM_X9_42_DH_DERIVE, p11_rpc_buffer_add_x9_42_dh1_derive_mechanism_value, p11_rpc_buffer_get_x9_42_dh1_derive_mechanism_value },
	{ CKM_X9_42_DH_HYBRID_DERIVE, p11_rpc_buffer_add_x9_42_dh2_derive_mechanism_value, p11_rpc_buffer_get_x9_42_dh2_derive_mechanism_value },
	{ CKM_X9_42_MQV_DERIVE, p11_rpc_buffer_add_x9_42_mqv_derive_mechanism_value, p11_rpc_buffer_get_x9_42_mqv_derive_mechanism_value },

	/* KEA */
	{ CKM_KEA_DERIVE, p11_rpc_buffer_add_kea_derive_mechanism_value, p11_rpc_buffer_get_kea_derive_mechanism_value },

	/* Generic secret key derivation */
	{ CKM_CONCATENATE_BASE_AND_KEY, p11_rpc_buffer_add_ulong_value, p11_rpc_buffer_get_ulong_value },
	{ CKM_EXTRACT_KEY_FROM_KEY, p11_rpc_buffer_add_ulong_value, p11_rpc_buffer_get_ulong_value },
	{ CKM_CONCATENATE_BASE_AND_DATA, p11_rpc_buffer_add_key_derivation_string_mechanism_value, p11_rpc_buffer_get_key_derivation_string_mechanism_value },
	{ CKM_CONCATENATE_DATA_AND_BASE, p11_rpc_buffer_add_key_derivation_string_mechanism_value, p11_rpc_buffer_get_key_derivation_string_mechanism_value },
	{ CKM_XOR_BASE_AND_DATA, p11_rpc_buffer_add_key_derivation_string_mechanism_value, p11_rpc_buffer_get_key_derivation_string_mechanism_value },

	/* ECB mode key derivation */
	{ CKM_AES_ECB_ENCRYPT_DATA, p11_rpc_buffer_add_key_derivation_string_mechanism_value, p11_rpc_buffer_get_key_derivation_string_mechanism_value },
	{ CKM_DES_ECB_ENCRYPT_DATA, p11_rpc_buffer_add_key_derivation_string_mechanism_value, p11_rpc_buffer_get_key_derivation_string_mechanism_value },
	{ CKM_DES3_ECB_ENCRYPT_DATA, p11_rpc_buffer_add_key_derivation_string_mechanism_value, p11_rpc_buffer_get_key_derivation_string_mechanism_value },
	{ CKM_CAMELLIA_ECB_ENCRYPT_DATA, p11_rpc_buffer_add_key_derivation_string_mechanism_value, p11_rpc_buffer_get_key_derivation_string_mechanism_value },
	{ CKM_ARIA_ECB_ENCRYPT_DATA, p11_rpc_buffer_add_key_derivation_string_mechanism_value, p11_rpc_buffer_get_key_derivation_string_mechanism_value },
	{ CKM_SEED_ECB_ENCRYPT_DATA, p11_rpc_buffer_add_key_derivation_string_mechanism_value, p11_rpc_buffer_get_key_derivation_string_mechanism_value },

	/* CBC mode key derivation */
	{ CKM_AES_CBC_ENCRYPT_DATA, p11_rpc_buffer_add_cbc_encrypt_data_mechanism_value, p11_rpc_buffer_get_cbc_encrypt_data_mechanism_value },
	{ CKM_CAMELLIA_CBC_ENCRYPT_DATA, p11_rpc_buffer_add_cbc_encrypt_data_mechanism_value, p11_rpc_buffer_get_cbc_encrypt_data_mechanism_value },
	{ CKM_ARIA_CBC_ENCRYPT_DATA, p11_rpc_buffer_add_cbc_encrypt_data_mechanism_value, p11_rpc_buffer_get_cbc_encrypt_data_mechanism_value },
	{ CKM_SEED_CBC_ENCRYPT_DATA, p11_rpc_buffer_add_cbc_encrypt_data_mechanism_value, p11_rpc_buffer_get_cbc_encrypt_data_mechanism_value },
	{ CKM_DES_CBC_ENCRYPT_DATA, p11_rpc_buffer_add_des_cbc_encrypt_data_mechanism_value, p11_rpc_buffer_get_des_cbc_encrypt_data_mechanism_value },
	{ CKM_DES3_CBC_ENCRYPT_DATA, p11_rpc_buffer_add_des_cbc_encrypt_data_mechanism_value, p11_rpc_buffer_get_des_cbc_encrypt_data_mechanism_value },

	/* AES, Camellia, ARIA and SEED modes taking an initialization vector */
	{ CKM_AES_XTS, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_AES_KEY_WRAP, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_AES_KEY_WRAP_PAD, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_AES_KEY_WRAP_KWP, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_AES_KEY_WRAP_PKCS7, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_AES_CCM, p11_rpc_buffer_add_aes_ccm_mechanism_value, p11_rpc_buffer_get_aes_ccm_mechanism_value },
	{ CKM_CAMELLIA_CBC, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_CAMELLIA_CBC_PAD, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	/* CK_CAMELLIA_CTR_PARAMS is laid out as CK_AES_CTR_PARAMS */
	{ CKM_CAMELLIA_CTR, p11_rpc_buffer_add_aes_ctr_mechanism_value, p11_rpc_buffer_get_aes_ctr_mechanism_value },
	{ CKM_ARIA_CBC, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_ARIA_CBC_PAD, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_SEED_CBC, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_SEED_CBC_PAD, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },

	/* Legacy block ciphers taking an initialization vector */
	{ CKM_DES_OFB8, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_CDMF_CBC, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_CDMF_CBC_PAD, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_CAST_CBC, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_CAST_CBC_PAD, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_CAST3_CBC, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_CAST3_CBC_PAD, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_CAST128_CBC, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_CAST128_CBC_PAD, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_IDEA_CBC, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_IDEA_CBC_PAD, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_BLOWFISH_CBC, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_BLOWFISH_CBC_PAD, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_TWOFISH_CBC, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_TWOFISH_CBC_PAD, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_GOST28147, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_GOST28147_KEY_WRAP, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_SKIPJACK_CBC64, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_SKIPJACK_OFB64, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_SKIPJACK_CFB64, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_SKIPJACK_CFB32, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_SKIPJACK_CFB16, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },
	{ CKM_SKIPJACK_CFB8, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value },

	/*
	 * RC2 and RC5.  These were dropped in PKCS #11 3.2, the parameters
	 * follow PKCS #11 3.0.  CKM_RC2_ECB, CKM_RC2_MAC, CKM_RC5_ECB and
	 * CKM_RC5_MAC are deliberately absent: mechanism_has_no_parameters()
	 * already claims them, and moving them here would change the wire
	 * format of mechanisms that are no longer part of the standard.
	 */
	{ CKM_RC2_CBC, p11_rpc_buffer_add_rc2_cbc_mechanism_value, p11_rpc_buffer_get_rc2_cbc_mechanism_value },
	{ CKM_RC2_CBC_PAD, p11_rpc_buffer_add_rc2_cbc_mechanism_value, p11_rpc_buffer_get_rc2_cbc_mechanism_value },
	{ CKM_RC2_MAC_GENERAL, p11_rpc_buffer_add_rc2_mac_general_mechanism_value, p11_rpc_buffer_get_rc2_mac_general_mechanism_value },
	{ CKM_RC5_CBC, p11_rpc_buffer_add_rc5_cbc_mechanism_value, p11_rpc_buffer_get_rc5_cbc_mechanism_value },
	{ CKM_RC5_CBC_PAD, p11_rpc_buffer_add_rc5_cbc_mechanism_value, p11_rpc_buffer_get_rc5_cbc_mechanism_value },
	{ CKM_RC5_MAC_GENERAL, p11_rpc_buffer_add_rc5_mac_general_mechanism_value, p11_rpc_buffer_get_rc5_mac_general_mechanism_value },

	/* Further general-length MACing mechanisms */
	{ CKM_MD2_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_MD5_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_RIPEMD128_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_RIPEMD160_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA3_224_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA3_256_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA3_384_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA3_512_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA512_T_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	/*
	 * SHA-512/t and the SSL 3.0 MACs take a CK_MAC_GENERAL_PARAMS too,
	 * holding t respectively the MAC length.  They used to be treated as
	 * taking no parameter at all, which dropped it on the floor.
	 */
	{ CKM_SHA512_T, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA512_T_HMAC, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SSL3_MD5_MAC, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SSL3_SHA1_MAC, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_BLAKE2B_160_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_BLAKE2B_256_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_BLAKE2B_384_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_BLAKE2B_512_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_DES_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_CDMF_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_CAST_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_CAST3_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_CAST128_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_IDEA_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_CAMELLIA_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_ARIA_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SEED_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },

	/* Stream ciphers */
	{ CKM_CHACHA20, p11_rpc_buffer_add_chacha20_mechanism_value, p11_rpc_buffer_get_chacha20_mechanism_value },
	{ CKM_SALSA20, p11_rpc_buffer_add_salsa20_mechanism_value, p11_rpc_buffer_get_salsa20_mechanism_value },
	{ CKM_CHACHA20_POLY1305, p11_rpc_buffer_add_poly1305_mechanism_value, p11_rpc_buffer_get_poly1305_mechanism_value },
	{ CKM_SALSA20_POLY1305, p11_rpc_buffer_add_poly1305_mechanism_value, p11_rpc_buffer_get_poly1305_mechanism_value },

	/* GOST */
	{ CKM_GOSTR3410_DERIVE, p11_rpc_buffer_add_gostr3410_derive_mechanism_value, p11_rpc_buffer_get_gostr3410_derive_mechanism_value },
	{ CKM_GOSTR3410_KEY_WRAP, p11_rpc_buffer_add_gostr3410_key_wrap_mechanism_value, p11_rpc_buffer_get_gostr3410_key_wrap_mechanism_value },

	/* HKDF */
	{ CKM_HKDF_DERIVE, p11_rpc_buffer_add_hkdf_mechanism_value, p11_rpc_buffer_get_hkdf_mechanism_value },
	{ CKM_HKDF_DATA, p11_rpc_buffer_add_hkdf_mechanism_value, p11_rpc_buffer_get_hkdf_mechanism_value },

	/* IKE */
	{ CKM_IKE_PRF_DERIVE, p11_rpc_buffer_add_ike_prf_derive_mechanism_value, p11_rpc_buffer_get_ike_prf_derive_mechanism_value },
	{ CKM_IKE1_PRF_DERIVE, p11_rpc_buffer_add_ike1_prf_derive_mechanism_value, p11_rpc_buffer_get_ike1_prf_derive_mechanism_value },
	{ CKM_IKE1_EXTENDED_DERIVE, p11_rpc_buffer_add_ike1_extended_derive_mechanism_value, p11_rpc_buffer_get_ike1_extended_derive_mechanism_value },
	{ CKM_IKE2_PRF_PLUS_DERIVE, p11_rpc_buffer_add_ike2_prf_plus_derive_mechanism_value, p11_rpc_buffer_get_ike2_prf_plus_derive_mechanism_value },

	/* SKIPJACK and legacy key wrapping */
	{ CKM_SKIPJACK_PRIVATE_WRAP, p11_rpc_buffer_add_skipjack_private_wrap_mechanism_value, p11_rpc_buffer_get_skipjack_private_wrap_mechanism_value },
	{ CKM_SKIPJACK_RELAYX, p11_rpc_buffer_add_skipjack_relayx_mechanism_value, p11_rpc_buffer_get_skipjack_relayx_mechanism_value },
	{ CKM_KEY_WRAP_SET_OAEP, p11_rpc_buffer_add_key_wrap_set_oaep_mechanism_value, p11_rpc_buffer_get_key_wrap_set_oaep_mechanism_value },

	/* Password based key derivation */
	{ CKM_PKCS5_PBKD2, p11_rpc_buffer_add_pkcs5_pbkd2_mechanism_value, p11_rpc_buffer_get_pkcs5_pbkd2_mechanism_value },

	/* SSL 3.0 and TLS */
	{ CKM_TLS_KDF, p11_rpc_buffer_add_tls_kdf_mechanism_value, p11_rpc_buffer_get_tls_kdf_mechanism_value },
	{ CKM_TLS12_KDF, p11_rpc_buffer_add_tls_kdf_mechanism_value, p11_rpc_buffer_get_tls_kdf_mechanism_value },
	{ CKM_TLS_MAC, p11_rpc_buffer_add_tls_mac_mechanism_value, p11_rpc_buffer_get_tls_mac_mechanism_value },
	{ CKM_TLS12_MAC, p11_rpc_buffer_add_tls_mac_mechanism_value, p11_rpc_buffer_get_tls_mac_mechanism_value },
};

static p11_rpc_mechanism_serializer p11_rpc_byte_array_mechanism_serializer = {
	0, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value
};

static bool
mechanism_has_sane_parameters (CK_MECHANISM_TYPE type)
{
	int i;

	/* This can be set from tests, to override default set of supported */
	if (p11_rpc_mechanisms_override_supported) {
		for (i = 0; p11_rpc_mechanisms_override_supported[i] != 0; i++) {
			if (p11_rpc_mechanisms_override_supported[i] == type)
				return true;
		}

		return false;
	}

	for (i = 0; i < ELEMS(p11_rpc_mechanism_serializers); i++) {
		if (p11_rpc_mechanism_serializers[i].type == type)
			return true;
	}

	return false;
}

static bool
mechanism_has_no_parameters (CK_MECHANISM_TYPE mech)
{
	/* This list is incomplete */

	switch (mech) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
	case CKM_RSA_X9_31_KEY_PAIR_GEN:
	case CKM_RSA_PKCS:
	case CKM_RSA_9796:
	case CKM_RSA_X_509:
	case CKM_RSA_X9_31:
	case CKM_MD2_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA224_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_RIPEMD128_RSA_PKCS:
	case CKM_RIPEMD160_RSA_PKCS:
	case CKM_SHA1_RSA_X9_31:
	case CKM_DSA_KEY_PAIR_GEN:
	case CKM_DSA_PARAMETER_GEN:
	case CKM_DSA:
	case CKM_DSA_SHA1:
	case CKM_FORTEZZA_TIMESTAMP:
	case CKM_EC_KEY_PAIR_GEN:
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_EC_EDWARDS_KEY_PAIR_GEN:
	case CKM_DH_PKCS_KEY_PAIR_GEN:
	case CKM_DH_PKCS_PARAMETER_GEN:
	case CKM_X9_42_DH_KEY_PAIR_GEN:
	case CKM_X9_42_DH_PARAMETER_GEN:
	case CKM_KEA_KEY_PAIR_GEN:
	case CKM_GENERIC_SECRET_KEY_GEN:
	case CKM_RC2_KEY_GEN:
	case CKM_RC4_KEY_GEN:
	case CKM_RC4:
	case CKM_RC5_KEY_GEN:
	case CKM_AES_KEY_GEN:
	case CKM_AES_ECB:
	case CKM_AES_MAC:
	case CKM_AES_CMAC:
	case CKM_DES_KEY_GEN:
	case CKM_DES2_KEY_GEN:
	case CKM_DES3_KEY_GEN:
	case CKM_CDMF_KEY_GEN:
	case CKM_CAST_KEY_GEN:
	case CKM_CAST3_KEY_GEN:
	case CKM_CAST128_KEY_GEN:
	case CKM_IDEA_KEY_GEN:
	case CKM_SSL3_PRE_MASTER_KEY_GEN:
	case CKM_TLS_PRE_MASTER_KEY_GEN:
	case CKM_SKIPJACK_KEY_GEN:
	case CKM_BATON_KEY_GEN:
	case CKM_JUNIPER_KEY_GEN:
	case CKM_RC2_ECB:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_CDMF_ECB:
	case CKM_CAST_ECB:
	case CKM_CAST3_ECB:
	case CKM_CAST128_ECB:
	case CKM_RC5_ECB:
	case CKM_IDEA_ECB:
	case CKM_RC2_MAC:
	case CKM_DES_MAC:
	case CKM_DES3_MAC:
	case CKM_DES3_CMAC:
	case CKM_CDMF_MAC:
	case CKM_CAST_MAC:
	case CKM_CAST3_MAC:
	case CKM_RC5_MAC:
	case CKM_IDEA_MAC:
	case CKM_SKIPJACK_WRAP:
	case CKM_BATON_WRAP:
	case CKM_JUNIPER_WRAP:
	case CKM_MD2:
	case CKM_MD2_HMAC:
	case CKM_MD5:
	case CKM_MD5_HMAC:
	case CKM_SHA_1:
	case CKM_SHA_1_HMAC:
	case CKM_SHA1_KEY_DERIVATION:
	case CKM_SHA224:
	case CKM_SHA224_HMAC:
	case CKM_SHA224_KEY_DERIVATION:
	case CKM_SHA256:
	case CKM_SHA256_HMAC:
	case CKM_SHA256_KEY_DERIVATION:
	case CKM_SHA384:
	case CKM_SHA384_HMAC:
	case CKM_SHA384_KEY_DERIVATION:
	case CKM_SHA512:
	case CKM_SHA512_HMAC:
	case CKM_SHA512_KEY_DERIVATION:
	case CKM_SHA512_T_KEY_DERIVATION:
	case CKM_SHA512_224:
	case CKM_SHA512_224_HMAC:
	case CKM_SHA512_224_KEY_DERIVATION:
	case CKM_SHA512_256:
	case CKM_SHA512_256_HMAC:
	case CKM_SHA512_256_KEY_DERIVATION:
	case CKM_FASTHASH:
	case CKM_RIPEMD128:
	case CKM_RIPEMD128_HMAC:
	case CKM_RIPEMD160:
	case CKM_RIPEMD160_HMAC:
	case CKM_KEY_WRAP_LYNKS:
	case CKM_IBM_SHA3_224:
	case CKM_IBM_SHA3_256:
	case CKM_IBM_SHA3_384:
	case CKM_IBM_SHA3_512:
	case CKM_IBM_CMAC:
	case CKM_IBM_DILITHIUM:
	case CKM_IBM_SHA3_224_HMAC:
	case CKM_IBM_SHA3_256_HMAC:
	case CKM_IBM_SHA3_384_HMAC:
	case CKM_IBM_SHA3_512_HMAC:
	case CKM_IBM_ED25519_SHA512:
	case CKM_IBM_ED448_SHA3:
	/* PKCS#11 3.2 */
	case CKM_ML_KEM_KEY_PAIR_GEN:
	case CKM_ML_KEM:
	case CKM_ML_DSA_KEY_PAIR_GEN:
	case CKM_SLH_DSA_KEY_PAIR_GEN:
	case CKM_HSS_KEY_PAIR_GEN:
	case CKM_HSS:
	case CKM_XMSS_KEY_PAIR_GEN:
	case CKM_XMSSMT_KEY_PAIR_GEN:
	case CKM_XMSS:
	case CKM_XMSSMT:
		return true;
	default:
		return false;
	};
}

bool
p11_rpc_mechanism_is_supported (CK_MECHANISM_TYPE mech)
{
	if (mechanism_has_no_parameters (mech) ||
	    mechanism_has_sane_parameters (mech))
		return true;
	return false;
}

void
p11_rpc_buffer_add_mechanism (p11_buffer *buffer, const CK_MECHANISM *mech)
{
	p11_rpc_mechanism_serializer *serializer = NULL;
	size_t i;

	/* The mechanism type */
	p11_rpc_buffer_add_uint32 (buffer, mech->mechanism);

	if (mechanism_has_no_parameters (mech->mechanism)) {
		return;
	}

	assert (mechanism_has_sane_parameters (mech->mechanism));

	if (mech->pParameter == NULL && mech->ulParameterLen == 0) {
		p11_rpc_buffer_add_byte (buffer, 0);
		return;
	} else {
		p11_rpc_buffer_add_byte (buffer, 1);
	}

	for (i = 0; i < ELEMS (p11_rpc_mechanism_serializers); i++) {
		if (p11_rpc_mechanism_serializers[i].type == mech->mechanism) {
			serializer = &p11_rpc_mechanism_serializers[i];
			break;
		}
	}

	if (serializer == NULL)
		serializer = &p11_rpc_byte_array_mechanism_serializer;

	serializer->encode (buffer, mech->pParameter, mech->ulParameterLen);
}

bool
p11_rpc_buffer_get_mechanism (p11_buffer *buffer,
			      size_t *offset,
			      CK_MECHANISM *mech)
{
	uint32_t mechanism;
	p11_rpc_mechanism_serializer *serializer = NULL;
	size_t i;
	unsigned char has_param;

	/* The mechanism type */
	if (!p11_rpc_buffer_get_uint32 (buffer, offset, &mechanism))
		return false;

	mech->mechanism = mechanism;

	/*
	 * The NULL mechanism is used for C_*Init () functions to
	 * cancel operation.  We use a special value 0xffffffff as a
	 * marker to indicate that.
	 */
	if (mechanism == 0xffffffff) {
		mech->ulParameterLen = 0;
		mech->pParameter = NULL;
		return true;
	} else if (mechanism_has_no_parameters (mech->mechanism)) {
		return true;
	}

	if (!p11_rpc_buffer_get_byte (buffer, offset, &has_param))
		return false;

	if (has_param == 0) {
		mech->ulParameterLen = 0;
		mech->pParameter = NULL;
		return true;
	}

	for (i = 0; i < ELEMS (p11_rpc_mechanism_serializers); i++) {
		if (p11_rpc_mechanism_serializers[i].type == mech->mechanism) {
			serializer = &p11_rpc_mechanism_serializers[i];
			break;
		}
	}

	if (serializer == NULL)
		serializer = &p11_rpc_byte_array_mechanism_serializer;

	if (!serializer->decode (buffer, offset, mech->pParameter,
				 &mech->ulParameterLen))
		return false;

	return true;
}

void
p11_rpc_buffer_add_mech_param_update (p11_buffer *buffer, const CK_MECHANISM *mech)
{
	p11_rpc_mechanism_serializer *serializer = NULL;
	size_t i;

	if (mechanism_has_no_parameters (mech->mechanism)) {
		return;
	}

	if (mech->pParameter == NULL && mech->ulParameterLen == 0) {
		p11_rpc_buffer_add_byte (buffer, 0);
		return;
	} else {
		p11_rpc_buffer_add_byte (buffer, 1);
	}

	for (i = 0; i < ELEMS (p11_rpc_mech_param_update_serializers); i++) {
		if (p11_rpc_mech_param_update_serializers[i].type == mech->mechanism) {
			serializer = &p11_rpc_mech_param_update_serializers[i];
			break;
		}
	}

	if (serializer == NULL)
		return;

	serializer->encode (buffer, mech->pParameter, mech->ulParameterLen);
}

bool
p11_rpc_buffer_get_mech_param_update (p11_buffer *buffer,
				      size_t *offset,
				      CK_MECHANISM *mech)
{
	p11_rpc_mechanism_serializer *serializer = NULL;
	size_t i;
	unsigned char has_param;

	if (mechanism_has_no_parameters (mech->mechanism)) {
		mech->ulParameterLen = 0;
		mech->pParameter = NULL;
		return true;
	}

	if (!p11_rpc_buffer_get_byte (buffer, offset, &has_param))
		return false;

	if (has_param == 0) {
		mech->ulParameterLen = 0;
		mech->pParameter = NULL;
		return true;
	}

	for (i = 0; i < ELEMS (p11_rpc_mech_param_update_serializers); i++) {
		if (p11_rpc_mech_param_update_serializers[i].type == mech->mechanism) {
			serializer = &p11_rpc_mech_param_update_serializers[i];
			break;
		}
	}

	if (serializer == NULL)
		return true;

	if (!serializer->decode (buffer, offset, mech->pParameter,
				 &mech->ulParameterLen))
		return false;

	return true;
}
