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

#include "asn1.h"
#define P11_DEBUG_FLAG P11_DEBUG_TRUST
#include "debug.h"
#include "oid.h"

#include "openssl.asn.h"
#include "pkix.asn.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void
free_asn1_def (void *data)
{
	node_asn *def = data;
	asn1_delete_structure (&def);
}

struct {
	const ASN1_ARRAY_TYPE* tab;
	const char *prefix;
	int prefix_len;
} asn1_tabs[] = {
	{ pkix_asn1_tab, "PKIX1.", 6 },
	{ openssl_asn1_tab, "OPENSSL.", 8 },
	{ NULL, },
};

p11_dict *
p11_asn1_defs_load (void)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = { 0, };
	node_asn *def;
	p11_dict *defs;
	int ret;
	int i;

	defs = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, free_asn1_def);

	for (i = 0; asn1_tabs[i].tab != NULL; i++) {

		def = NULL;
		ret = asn1_array2tree (asn1_tabs[i].tab, &def, message);
		if (ret != ASN1_SUCCESS) {
			p11_debug_precond ("failed to load %s* definitions: %s: %s\n",
			                   asn1_tabs[i].prefix, asn1_strerror (ret), message);
			return NULL;
		}

		if (!p11_dict_set (defs, (void *)asn1_tabs[i].prefix, def))
			return_val_if_reached (NULL);
	}

	return defs;
}

static node_asn *
lookup_def (p11_dict *asn1_defs,
            const char *struct_name)
{
	int i;

	for (i = 0; asn1_tabs[i].tab != NULL; i++) {
		if (strncmp (struct_name, asn1_tabs[i].prefix, asn1_tabs[i].prefix_len) == 0)
			return p11_dict_get (asn1_defs, asn1_tabs[i].prefix);
	}

	p11_debug_precond ("unknown prefix for element: %s\n", struct_name);
	return NULL;
}

node_asn *
p11_asn1_create (p11_dict *asn1_defs,
                 const char *struct_name)
{
	node_asn *def;
	node_asn *asn;
	int ret;

	return_val_if_fail (asn1_defs != NULL, NULL);

	def = lookup_def (asn1_defs, struct_name);
	return_val_if_fail (def != NULL, NULL);

	ret = asn1_create_element (def, struct_name, &asn);
	if (ret != ASN1_SUCCESS) {
		p11_debug_precond ("failed to create element %s: %s\n",
		                   struct_name, asn1_strerror (ret));
		return NULL;
	}

	return asn;
}

node_asn *
p11_asn1_decode (p11_dict *asn1_defs,
                 const char *struct_name,
                 const unsigned char *der,
                 size_t der_len,
                 char *message)
{
	char msg[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	node_asn *asn = NULL;
	int ret;

	return_val_if_fail (asn1_defs != NULL, NULL);

	asn = p11_asn1_create (asn1_defs, struct_name);
	return_val_if_fail (asn != NULL, NULL);

	/* asn1_der_decoding destroys the element if fails */
	ret = asn1_der_decoding (&asn, der, der_len, message ? message : msg);

	if (ret != ASN1_SUCCESS) {
		/* If caller passed in a message buffer, assume they're logging */
		if (!message) {
			p11_debug ("couldn't parse %s: %s: %s",
			           struct_name, asn1_strerror (ret), msg);
		}
		return NULL;
	}

	return asn;
}

unsigned char *
p11_asn1_encode (node_asn *asn,
                 size_t *der_len)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	unsigned char *der;
	int len;
	int ret;

	return_val_if_fail (der_len != NULL, NULL);

	len = 0;
	ret = asn1_der_coding (asn, "", NULL, &len, message);
	return_val_if_fail (ret != ASN1_SUCCESS, NULL);

	if (ret == ASN1_MEM_ERROR) {
		der = malloc (len);
		return_val_if_fail (der != NULL, NULL);

		ret = asn1_der_coding (asn, "", der, &len, message);
	}

	if (ret != ASN1_SUCCESS) {
		p11_debug_precond ("failed to encode: %s\n", message);
		return NULL;
	}

	if (der_len)
		*der_len = len;
	return der;
}

void *
p11_asn1_read (node_asn *asn,
               const char *field,
               size_t *length)
{
	unsigned char *value;
	int len;
	int ret;

	return_val_if_fail (asn != NULL, NULL);
	return_val_if_fail (field != NULL, NULL);
	return_val_if_fail (length != NULL, NULL);

	len = 0;
	ret = asn1_read_value (asn, field, NULL, &len);
	if (ret == ASN1_ELEMENT_NOT_FOUND)
		return NULL;

	return_val_if_fail (ret == ASN1_MEM_ERROR, NULL);

	value = malloc (len + 1);
	return_val_if_fail (value != NULL, NULL);

	ret = asn1_read_value (asn, field, value, &len);
	return_val_if_fail (ret == ASN1_SUCCESS, NULL);

	/* Courtesy zero terminated */
	value[len] = '\0';

	*length = len;
	return value;
}

void
p11_asn1_free (void *asn)
{
	node_asn *node = asn;
	if (node != NULL)
		asn1_delete_structure (&node);
}

ssize_t
p11_asn1_tlv_length (const unsigned char *data,
                     size_t length)
{
	unsigned char cls;
	int counter = 0;
	int cb, len;
	unsigned long tag;

	if (asn1_get_tag_der (data, length, &cls, &cb, &tag) == ASN1_SUCCESS) {
		counter += cb;
		len = asn1_get_length_der (data + cb, length - cb, &cb);
		counter += cb;
		if (len >= 0) {
			len += counter;
			if (length >= len)
				return len;
		}
	}

	return -1;
}

typedef struct {
	node_asn *node;
	char *struct_name;
	size_t length;
} asn1_item;

static void
free_asn1_item (void *data)
{
	asn1_item *item = data;
	free (item->struct_name);
	asn1_delete_structure (&item->node);
	free (item);
}

struct _p11_asn1_cache {
	p11_dict *defs;
	p11_dict *items;
};

p11_asn1_cache *
p11_asn1_cache_new (void)
{
	p11_asn1_cache *cache;

	cache = calloc (1, sizeof (p11_asn1_cache));
	return_val_if_fail (cache != NULL, NULL);

	cache->defs = p11_asn1_defs_load ();
	return_val_if_fail (cache->defs != NULL, NULL);

	cache->items = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal,
	                             NULL, free_asn1_item);
	return_val_if_fail (cache->items != NULL, NULL);

	return cache;
}

node_asn *
p11_asn1_cache_get (p11_asn1_cache *cache,
                    const char *struct_name,
                    const unsigned char *der,
                    size_t der_len)
{
	asn1_item *item;

	if (cache == NULL)
		return NULL;

	return_val_if_fail (struct_name != NULL, NULL);
	return_val_if_fail (der != NULL, NULL);

	item = p11_dict_get (cache->items, der);
	if (item != NULL) {
		return_val_if_fail (item->length == der_len, NULL);
		return_val_if_fail (strcmp (item->struct_name, struct_name) == 0, NULL);
		return item->node;
	}

	return NULL;
}

void
p11_asn1_cache_take (p11_asn1_cache *cache,
                     node_asn *node,
                     const char *struct_name,
                     const unsigned char *der,
                     size_t der_len)
{
	asn1_item *item;

	if (cache == NULL) {
		asn1_delete_structure (&node);
		return;
	}

	return_if_fail (struct_name != NULL);
	return_if_fail (der != NULL);
	return_if_fail (der_len != 0);

	item = calloc (1, sizeof (asn1_item));
	return_if_fail (item != NULL);

	item->length = der_len;
	item->node = node;
	item->struct_name = strdup (struct_name);
	return_if_fail (item->struct_name != NULL);

	if (!p11_dict_set (cache->items, (void *)der, item))
		return_if_reached ();
}

void
p11_asn1_cache_flush (p11_asn1_cache *cache)
{
	if (cache == NULL)
		return;
	p11_dict_clear (cache->items);
}

p11_dict *
p11_asn1_cache_defs (p11_asn1_cache *cache)
{
	return_val_if_fail (cache != NULL, NULL);
	return cache->defs;
}

void
p11_asn1_cache_free (p11_asn1_cache *cache)
{
	if (!cache)
		return;
	p11_dict_free (cache->items);
	p11_dict_free (cache->defs);
	free (cache);
}
