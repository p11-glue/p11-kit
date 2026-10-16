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

void
p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value (p11_buffer *buffer,
						 const void *value,
						 CK_ULONG value_length)
{
	CK_RSA_PKCS_PSS_PARAMS params;

	/* Check if value can be converted to CK_RSA_PKCS_PSS_PARAMS. */
	if (value_length != sizeof (CK_RSA_PKCS_PSS_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.hashAlg, params.mgf, and params.sLen can be
	 * converted to uint64_t. */
	if (params.hashAlg > UINT64_MAX || params.mgf > UINT64_MAX ||
	    params.sLen > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

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
	uint64_t val[3];

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[0]))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[1]))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[2]))
		return false;

	if (value) {
		CK_RSA_PKCS_PSS_PARAMS params;

		params.hashAlg = val[0];
		params.mgf = val[1];
		params.sLen = val[2];

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

	/* Check if value can be converted to CK_RSA_PKCS_OAEP_PARAMS. */
	if (value_length != sizeof (CK_RSA_PKCS_OAEP_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.hashAlg, params.mgf, and params.source can be
	 * converted to uint64_t. */
	if (params.hashAlg > UINT64_MAX || params.mgf > UINT64_MAX ||
	    params.source > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.hashAlg);
	p11_rpc_buffer_add_uint64 (buffer, params.mgf);
	p11_rpc_buffer_add_uint64 (buffer, params.source);

	/* parmas.pSourceData can only be an array of CK_BYTE or
	 * NULL */
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.pSourceData,
				       params.ulSourceDataLen);
}

bool
p11_rpc_buffer_get_rsa_pkcs_oaep_mechanism_value (p11_buffer *buffer,
						  size_t *offset,
						  void *value,
						  CK_ULONG *value_length)
{
	uint64_t val[3];
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[0]))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[1]))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[2]))
		return false;
	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (value) {
		CK_RSA_PKCS_OAEP_PARAMS params;

		params.hashAlg = val[0];
		params.mgf = val[1];
		params.source = val[2];
		params.pSourceData = (void *) data;
		params.ulSourceDataLen = len;

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

	/* Check if value can be converted to CK_ECDH1_DERIVE_PARAMS. */
	if (value_length != sizeof (CK_ECDH1_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.kdf can be converted to uint64_t. */
	if (params.kdf > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.kdf);

	/* parmas.pSharedData can only be an array of CK_BYTE or
	 * NULL */
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.pSharedData,
				       params.ulSharedDataLen);

	/* parmas.pPublicData can only be an array of CK_BYTE or
	 * NULL */
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.pPublicData,
				       params.ulPublicDataLen);
}

bool
p11_rpc_buffer_get_ecdh1_derive_mechanism_value (p11_buffer *buffer,
						 size_t *offset,
						 void *value,
						 CK_ULONG *value_length)
{
	uint64_t val;
	const unsigned char *data1, *data2;
	size_t len1, len2;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val))
		return false;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data1, &len1))
		return false;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data2, &len2))
		return false;


	if (value) {
		CK_ECDH1_DERIVE_PARAMS params;

		params.kdf = val;
		params.pSharedData = (void *) data1;
		params.ulSharedDataLen = len1;
		params.pPublicData = (void *) data2;
		params.ulPublicDataLen = len2;

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

	/* Check if value can be converted to CKM_IBM_ATTRIBUTEBOUND_WRAP. */
	if (value_length != sizeof (CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.hSignVerifyKey can be converted to uint64_t. */
	if (params.hSignVerifyKey > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.hSignVerifyKey);
}

bool
p11_rpc_buffer_get_ibm_attrbound_wrap_mechanism_value (p11_buffer *buffer,
						       size_t *offset,
						       void *value,
						       CK_ULONG *value_length)
{
	uint64_t val = 0;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val))
		return false;

	if (value) {
		CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS params = { 0 };

		params.hSignVerifyKey = val;

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
		p11_rpc_buffer_add_byte(buffer, CK_IBM_KYBER_KEM_ENCAPSULATE);

		if (params.pCipher == NULL) {
			p11_rpc_buffer_add_byte(buffer, 0);
			p11_rpc_buffer_add_uint32(buffer, params.ulCipherLen);
		} else {
			p11_rpc_buffer_add_byte(buffer, 1);
			p11_rpc_buffer_add_byte_array(buffer, (unsigned char *)params.pCipher, params.ulCipherLen);
		}
	} else {
		p11_rpc_buffer_add_byte(buffer, CK_IBM_KYBER_KEM_DECAPSULATE);
	}
}

bool
p11_rpc_buffer_get_ibm_kyber_mech_param_update (p11_buffer *buffer,
					 size_t *offset,
					 void *value,
					 CK_ULONG *value_length)
{
	const unsigned char *data;
	size_t len;
	unsigned char has_data;
	unsigned char capsulation;
	uint32_t length;

	if (!p11_rpc_buffer_get_byte(buffer, offset, &capsulation))
		return false;

	if (capsulation == CK_IBM_KYBER_KEM_ENCAPSULATE) {
		if (!p11_rpc_buffer_get_byte(buffer, offset, &has_data))
			return false;

		if (has_data) {
			if (!p11_rpc_buffer_get_byte_array(buffer, offset, &data, &len))
				return false;
		} else {
			if (!p11_rpc_buffer_get_uint32(buffer, offset, &length))
				return false;
			len = length;
		}

		if (value) {
			CK_IBM_KYBER_PARAMS *params = (CK_IBM_KYBER_PARAMS *) value;

			if (has_data) {
				assert (data != NULL);

				if (params->pCipher && params->ulCipherLen == len)
					memcpy(params->pCipher, data, len);
				else
					params->pCipher = (void *) data;
			}
			params->ulCipherLen = len;
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
		p11_rpc_buffer_add_byte(buffer, 0);
		p11_rpc_buffer_add_uint32(buffer, params.ulChainCodeLen);
	} else {
		p11_rpc_buffer_add_byte(buffer, 1);
		p11_rpc_buffer_add_byte_array(buffer, (unsigned char *)params.pChainCode, params.ulChainCodeLen);
	}
}

bool
p11_rpc_buffer_get_ibm_btc_derive_mech_param_update (p11_buffer *buffer,
					 size_t *offset,
					 void *value,
					 CK_ULONG *value_length)
{
	const unsigned char *data;
	unsigned char has_data;
	size_t len;
	uint32_t length;

	if (!p11_rpc_buffer_get_byte(buffer, offset, &has_data))
		return false;

	if (has_data) {
		if (!p11_rpc_buffer_get_byte_array(buffer, offset, &data, &len))
			return false;
	} else {
		if (!p11_rpc_buffer_get_uint32(buffer, offset, &length))
			return false;
		len = length;
	}

	if (value) {
		CK_IBM_BTC_DERIVE_PARAMS *params = (CK_IBM_BTC_DERIVE_PARAMS *) value;

		if (has_data) {
			assert (data != NULL);

			if (params->pChainCode && params->ulChainCodeLen == len)
				memcpy(params->pChainCode, data, len);
			else
				params->pChainCode = (void *) data;
		}
		params->ulChainCodeLen = len;
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

	if (params.submechanism > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.submechanism);
}

bool
p11_rpc_buffer_get_ibm_ecdsa_other_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	uint64_t val1;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val1))
		return false;

	if (value) {
		CK_IBM_ECDSA_OTHER_PARAMS params;

		params.submechanism = val1;

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

	if (params.type > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}
	p11_rpc_buffer_add_uint64(buffer, params.type);

	if (params.childKeyIndex > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}
	p11_rpc_buffer_add_uint64(buffer, params.childKeyIndex);

	p11_rpc_buffer_add_byte_array(buffer, (unsigned char *)params.pChainCode, params.ulChainCodeLen);

	if (params.version > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}
	p11_rpc_buffer_add_uint64(buffer, params.version);
}

bool
p11_rpc_buffer_get_ibm_btc_derive_mechanism_value (p11_buffer *buffer,
						   size_t *offset,
						   void *value,
						   CK_ULONG *value_length)
{
	uint64_t val1;
	uint64_t val2;
	size_t len;
	const unsigned char *data;
	uint64_t val3;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val1) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &val2) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &val3))
		return false;

	if (value) {
		CK_IBM_BTC_DERIVE_PARAMS params = { 0 };

		params.type = val1;
		params.childKeyIndex = val2;
		params.ulChainCodeLen = len;
		params.pChainCode = (void *) data;
		params.version = val3;

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

	if (params.ulVersion > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}
	p11_rpc_buffer_add_uint64(buffer, params.ulVersion);

	if (params.mode > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}
	p11_rpc_buffer_add_uint64(buffer, params.mode);

	if (params.kdf > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}
	p11_rpc_buffer_add_uint64(buffer, params.kdf);

	if (params.bPrepend > sizeof(CK_BBOOL)) {
		p11_buffer_fail(buffer);
		return;
	}
	p11_rpc_buffer_add_byte(buffer, (unsigned char) params.bPrepend);

	p11_rpc_buffer_add_byte_array(buffer, (unsigned char *)params.pCipher, params.ulCipherLen);

	p11_rpc_buffer_add_byte_array(buffer, (unsigned char *)params.pSharedData, params.ulSharedDataLen);

	if (params.hSecret > sizeof(CK_OBJECT_HANDLE)) {
		p11_buffer_fail(buffer);
		return;
	}
	p11_rpc_buffer_add_uint64(buffer, params.hSecret);
}

bool
p11_rpc_buffer_get_ibm_kyber_mechanism_value (p11_buffer *buffer,
					      size_t *offset,
					      void *value,
					      CK_ULONG *value_length)
{
	uint64_t val1;
	uint64_t val2;
	uint64_t val3;
	unsigned char byte;
	const unsigned char *data1;
	size_t len1;
	const unsigned char *data2;
	size_t len2;
	uint64_t val4;

	if (!p11_rpc_buffer_get_uint64(buffer, offset, &val1) ||
	    !p11_rpc_buffer_get_uint64(buffer, offset, &val2) ||
	    !p11_rpc_buffer_get_uint64(buffer, offset, &val3) ||
	    !p11_rpc_buffer_get_byte(buffer, offset, &byte) ||
	    !p11_rpc_buffer_get_byte_array(buffer, offset, &data1, &len1) ||
	    !p11_rpc_buffer_get_byte_array(buffer, offset, &data2, &len2) ||
	    !p11_rpc_buffer_get_uint64(buffer, offset, &val4))
		return false;

	if (value) {
		CK_IBM_KYBER_PARAMS *params = (CK_IBM_KYBER_PARAMS *) value;

		params->ulVersion = val1;
		params->mode = val2;
		params->kdf = val3;
		params->bPrepend = byte;
		if (params->pCipher && params->ulCipherLen == len1) {
			memcpy(params->pCipher, data1, len1);
			params->ulCipherLen = len1;
		} else {
			params->pCipher = (void *) data1;
			params->ulCipherLen = len1;
		}
		if (params->pSharedData && params->ulSharedDataLen == len2) {
			memcpy(params->pSharedData, data2, len2);
			params->ulSharedDataLen = len2;
		} else {
			params->pSharedData = (void *) data2;
			params->ulSharedDataLen = len2;
		}
		params->hSecret = val4;
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
	/* Check if value can be converted to an AES IV. */
	if (value_length != 16) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)value,
				       value_length);
}

bool
p11_rpc_buffer_get_aes_iv_mechanism_value (p11_buffer *buffer,
					   size_t *offset,
					   void *value,
					   CK_ULONG *value_length)
{
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (len != 16)
		return false;

	if (value)
		memcpy (value, data, len);

	if (value_length)
		*value_length = len;

	return true;
}

void
p11_rpc_buffer_add_aes_ctr_mechanism_value (p11_buffer *buffer,
					    const void *value,
					    CK_ULONG value_length)
{
	CK_AES_CTR_PARAMS params;

	/* Check if value can be converted to CK_AES_CTR_PARAMS. */
	if (value_length != sizeof (CK_AES_CTR_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.ulCounterBits can be converted to uint64_t. */
	if (params.ulCounterBits > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.ulCounterBits);

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.cb,
				       sizeof(params.cb));
}

bool
p11_rpc_buffer_get_aes_ctr_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	uint64_t val;
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val))
		return false;
	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (value) {
		CK_AES_CTR_PARAMS params;

		params.ulCounterBits = val;

		if (len != sizeof (params.cb))
			return false;

		memcpy (params.cb, data, sizeof (params.cb));
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

	/* Check if value can be converted to CK_GCM_PARAMS. */
	if (value_length != sizeof (CK_GCM_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.ulTagBits/ulIvBits can be converted to uint64_t. */
	if (params.ulTagBits > UINT64_MAX || params.ulIvBits > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.pIv,
				       params.ulIvLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulIvBits);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.pAAD,
				       params.ulAADLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulTagBits);
}

bool
p11_rpc_buffer_get_aes_gcm_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	uint64_t val1, val2;
	const unsigned char *data1, *data2;
	size_t len1, len2;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data1, &len1))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val1))
		return false;
	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data2, &len2))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val2))
		return false;

	if (value) {
		CK_GCM_PARAMS params;

		params.pIv = (void *) data1;
		params.ulIvLen = len1;
		params.ulIvBits = val1;
		params.pAAD = (void *) data2;
		params.ulAADLen = len2;
		params.ulTagBits = val2;

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
	/* Check if value can be converted to an DES IV. */
	if (value_length != 8) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)value,
				       value_length);
}

bool
p11_rpc_buffer_get_des_iv_mechanism_value (p11_buffer *buffer,
					   size_t *offset,
					   void *value,
					   CK_ULONG *value_length)
{
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (len != 8)
		return false;

	if (value)
		memcpy (value, data, len);

	if (value_length)
		*value_length = len;

	return true;
}

void
p11_rpc_buffer_add_mac_general_mechanism_value (p11_buffer *buffer,
						const void *value,
						CK_ULONG value_length)
{
	CK_ULONG val;
	uint64_t params;

	/*
	 * Check if value can be converted to an CK_MAC_GENERAL_PARAMS which
	 * is a CK_ULONG.
	 */
	if (value_length != sizeof (CK_ULONG)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&val, value, value_length);
	params = val;

	p11_rpc_buffer_add_uint64 (buffer, params);
}

bool
p11_rpc_buffer_get_mac_general_mechanism_value (p11_buffer *buffer,
						size_t *offset,
						void *value,
						CK_ULONG *value_length)
{
	uint64_t val;
	CK_ULONG params;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val))
		return false;

	params = val;

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
				       (unsigned char *)value,
				       value_length);
}

bool
p11_rpc_buffer_get_dh_pkcs_derive_mechanism_value (p11_buffer *buffer,
						   size_t *offset,
						   void *value,
						   CK_ULONG *value_length)
{
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (len == 0)
		return false;

	if (value)
		memcpy (value, data, len);

	if (value_length)
		*value_length = len;

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
				       (unsigned char *)params.pContextData,
				       params.ulContextDataLen);
}

bool
p11_rpc_buffer_get_eddsa_mechanism_value (p11_buffer *buffer,
					  size_t *offset,
					  void *value,
					  CK_ULONG *value_length)
{
	unsigned char flag;
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_byte (buffer, offset, &flag) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (value) {
		CK_EDDSA_PARAMS params;

		params.phFlag = flag ? CK_TRUE : CK_FALSE;
		params.pContextData = (void *) data;
		params.ulContextDataLen = len;

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

	if (params.hedgeVariant > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.hedgeVariant);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.pContext,
				       params.ulContextLen);
}

bool
p11_rpc_buffer_get_sign_additional_context_mechanism_value (p11_buffer *buffer,
							    size_t *offset,
							    void *value,
							    CK_ULONG *value_length)
{
	uint64_t hedge_variant;
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &hedge_variant) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (value) {
		CK_SIGN_ADDITIONAL_CONTEXT params;

		params.hedgeVariant = hedge_variant;
		params.pContext = (void *) data;
		params.ulContextLen = len;

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

	if (params.hedgeVariant > UINT64_MAX || params.hash > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.hedgeVariant);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.pContext,
				       params.ulContextLen);
	p11_rpc_buffer_add_uint64 (buffer, params.hash);
}

bool
p11_rpc_buffer_get_hash_sign_additional_context_mechanism_value (p11_buffer *buffer,
								 size_t *offset,
								 void *value,
								 CK_ULONG *value_length)
{
	uint64_t hedge_variant, hash;
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &hedge_variant) ||
	    !p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len) ||
	    !p11_rpc_buffer_get_uint64 (buffer, offset, &hash))
		return false;

	if (value) {
		CK_HASH_SIGN_ADDITIONAL_CONTEXT params;

		params.hedgeVariant = hedge_variant;
		params.pContext = (void *) data;
		params.ulContextLen = len;
		params.hash = hash;

		memcpy (value, &params, sizeof (CK_HASH_SIGN_ADDITIONAL_CONTEXT));
	}

	if (value_length)
		*value_length = sizeof (CK_HASH_SIGN_ADDITIONAL_CONTEXT);

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
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
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
	case CKM_SHA512_T:
	case CKM_SHA512_T_HMAC:
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

	if (!p11_rpc_buffer_get_byte(buffer, offset, &has_param))
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

	if (!serializer->decode (buffer, offset,
				 mech->pParameter, &mech->ulParameterLen))
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

	if (!p11_rpc_buffer_get_byte(buffer, offset, &has_param))
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

	if (!serializer->decode (buffer, offset,
				 mech->pParameter, &mech->ulParameterLen))
		return false;

	return true;
}
