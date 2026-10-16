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

void             p11_rpc_buffer_add_ibm_kyber_mech_param_update (p11_buffer *buffer,
							  const void *value,
							  CK_ULONG value_length);

bool             p11_rpc_buffer_get_ibm_kyber_mech_param_update (p11_buffer *buffer,
							  size_t *offset,
							  void *value,
							  CK_ULONG *value_length);

void             p11_rpc_buffer_add_ibm_btc_derive_mech_param_update (p11_buffer *buffer,
							       const void *value,
							       CK_ULONG value_length);

bool             p11_rpc_buffer_get_ibm_btc_derive_mech_param_update (p11_buffer *buffer,
							       size_t *offset,
							       void *value,
							       CK_ULONG *value_length);

void             p11_rpc_buffer_add_mech_param_update            (p11_buffer *buffer,
							  const CK_MECHANISM *mech);

bool             p11_rpc_buffer_get_mech_param_update            (p11_buffer *buffer,
							  size_t *offset,
							  CK_MECHANISM *mech);

void             p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value
                                                         (p11_buffer *buffer,
							  const void *value,
							  CK_ULONG value_length);

bool             p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value
                                                         (p11_buffer *buffer,
							  size_t *offset,
							  void *value,
							  CK_ULONG *value_length);

void             p11_rpc_buffer_add_rsa_pkcs_oaep_mechanism_value
                                                          (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool             p11_rpc_buffer_get_rsa_pkcs_oaep_mechanism_value
                                                          (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void            p11_rpc_buffer_add_ecdh1_derive_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool            p11_rpc_buffer_get_ecdh1_derive_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void            p11_rpc_buffer_add_eddsa_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool            p11_rpc_buffer_get_eddsa_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void            p11_rpc_buffer_add_sign_additional_context_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool            p11_rpc_buffer_get_sign_additional_context_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void            p11_rpc_buffer_add_hash_sign_additional_context_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool            p11_rpc_buffer_get_hash_sign_additional_context_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void            p11_rpc_buffer_add_ibm_attrbound_wrap_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool            p11_rpc_buffer_get_ibm_attrbound_wrap_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void            p11_rpc_buffer_add_ibm_ecdsa_other_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool            p11_rpc_buffer_get_ibm_ecdsa_other_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void            p11_rpc_buffer_add_ibm_btc_derive_mechanism_value
							(p11_buffer *buffer,
							const void *value,
							CK_ULONG value_length);

bool            p11_rpc_buffer_get_ibm_btc_derive_mechanism_value
						   (p11_buffer *buffer,
						   size_t *offset,
						   void *value,
						   CK_ULONG *value_length);

void            p11_rpc_buffer_add_ibm_kyber_mechanism_value
						   (p11_buffer *buffer,
						   const void *value,
						   CK_ULONG value_length);

bool            p11_rpc_buffer_get_ibm_kyber_mechanism_value
						  (p11_buffer *buffer,
						   size_t *offset,
						   void *value,
						   CK_ULONG *value_length);

void		p11_rpc_buffer_add_aes_iv_mechanism_value (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool		p11_rpc_buffer_get_aes_iv_mechanism_value (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void		p11_rpc_buffer_add_aes_ctr_mechanism_value (p11_buffer *buffer,
							    const void *value,
							    CK_ULONG value_length);

bool		p11_rpc_buffer_get_aes_ctr_mechanism_value (p11_buffer *buffer,
							    size_t *offset,
							    void *value,
							    CK_ULONG *value_length);

void		p11_rpc_buffer_add_aes_gcm_mechanism_value (p11_buffer *buffer,
							    const void *value,
							    CK_ULONG value_length);

bool		p11_rpc_buffer_get_aes_gcm_mechanism_value (p11_buffer *buffer,
							    size_t *offset,
							    void *value,
							    CK_ULONG *value_length);

void		p11_rpc_buffer_add_des_iv_mechanism_value (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool		p11_rpc_buffer_get_des_iv_mechanism_value (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void		p11_rpc_buffer_add_mac_general_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool		p11_rpc_buffer_get_mac_general_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void		p11_rpc_buffer_add_dh_pkcs_derive_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool		p11_rpc_buffer_get_dh_pkcs_derive_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

#endif /* _RPC_MECHANISM_H */
