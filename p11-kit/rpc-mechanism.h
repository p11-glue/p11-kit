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

#ifndef _RPC_MECHANISM_H
#define _RPC_MECHANISM_H

#include "rpc-message.h"

bool             p11_rpc_mechanism_is_supported          (CK_MECHANISM_TYPE mech);

void             p11_rpc_buffer_add_mechanism            (p11_buffer *buffer,
							  const CK_MECHANISM *mech);

bool             p11_rpc_buffer_get_mechanism            (p11_buffer *buffer,
							  size_t *offset,
							  CK_MECHANISM *mech);

void             p11_rpc_buffer_add_mech_param_update            (p11_buffer *buffer,
							  const CK_MECHANISM *mech);

bool             p11_rpc_buffer_get_mech_param_update            (p11_buffer *buffer,
							  size_t *offset,
							  CK_MECHANISM *mech);

#define P11_RPC_DECLARE_MECHANISM_VALUE(name)				\
	void	p11_rpc_buffer_add_ ## name (p11_buffer *buffer,	\
					     const void *value,		\
					     CK_ULONG value_length);	\
	bool	p11_rpc_buffer_get_ ## name (p11_buffer *buffer,	\
					     size_t *offset,		\
					     void *value,		\
					     CK_ULONG *value_length)

P11_RPC_DECLARE_MECHANISM_VALUE (ibm_kyber_mech_param_update);
P11_RPC_DECLARE_MECHANISM_VALUE (ibm_btc_derive_mech_param_update);
P11_RPC_DECLARE_MECHANISM_VALUE (rsa_pkcs_pss_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (rsa_pkcs_oaep_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (ecdh1_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (eddsa_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (sign_additional_context_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (hash_sign_additional_context_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (ibm_attrbound_wrap_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (ibm_ecdsa_other_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (ibm_btc_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (ibm_kyber_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (aes_iv_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (aes_ctr_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (aes_gcm_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (des_iv_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (mac_general_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (dh_pkcs_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (rc2_cbc_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (rc2_mac_general_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (rc5_cbc_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (rc5_mac_general_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (xeddsa_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (dsa_parameter_gen_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (ecdh_aes_key_wrap_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (key_derivation_string_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (cbc_encrypt_data_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (des_cbc_encrypt_data_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (ecmqv_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (x9_42_dh1_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (x9_42_dh2_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (x9_42_mqv_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (kea_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (aes_ccm_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (chacha20_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (salsa20_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (poly1305_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (gostr3410_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (gostr3410_key_wrap_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (hkdf_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (ike_prf_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (ike1_prf_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (ike1_extended_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (ike2_prf_plus_derive_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (key_wrap_set_oaep_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (skipjack_private_wrap_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (skipjack_relayx_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (pkcs5_pbkd2_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (tls_mac_mechanism_value);
P11_RPC_DECLARE_MECHANISM_VALUE (tls_kdf_mechanism_value);

#endif /* _RPC_MECHANISM_H */
