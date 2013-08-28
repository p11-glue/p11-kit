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
#include "buffer.h"
#include "compat.h"
#include "debug.h"
#include "extract.h"
#include "digest.h"
#include "message.h"
#include "save.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void
encode_msb_short (unsigned char *data,
                  int16_t value)
{
	uint16_t v;

	/* At this point we only support positive numbers */
	assert (value >= 0);
	assert (value < INT16_MAX);

	v = (uint16_t)value;
	data[0] = (v >> 8) & 0xff;
	data[1] = (v >> 0) & 0xff;
}

static void
encode_msb_int (unsigned char *data,
                int32_t value)
{
	uint32_t v;

	/* At this point we only support positive numbers */
	assert (value >= 0);
	assert (value < INT32_MAX);

	v = (uint32_t)value;
	data[0] = (v >> 24) & 0xff;
	data[1] = (v >> 16) & 0xff;
	data[2] = (v >> 8) & 0xff;
	data[3] = (v >> 0) & 0xff;
}

static void
encode_msb_long (unsigned char *data,
                 int64_t value)
{
	uint64_t v;

	/* At this point we only support positive numbers */
	assert (value >= 0);
	assert (value < INT64_MAX);

	v = (uint64_t)value;
	data[0] = (v >> 56) & 0xff;
	data[1] = (v >> 48) & 0xff;
	data[2] = (v >> 40) & 0xff;
	data[3] = (v >> 32) & 0xff;
	data[4] = (v >> 24) & 0xff;
	data[5] = (v >> 16) & 0xff;
	data[6] = (v >> 8) & 0xff;
	data[7] = (v >> 0) & 0xff;
}

static void
add_msb_int (p11_buffer *buffer,
             int32_t value)
{
	unsigned char *data = p11_buffer_append (buffer, 4);
	return_if_fail (data != NULL);
	encode_msb_int (data, value);
}

static void
add_msb_long (p11_buffer *buffer,
              int64_t value)
{
	unsigned char *data = p11_buffer_append (buffer, 8);
	return_if_fail (data != NULL);
	encode_msb_long (data, value);
}

static void
add_string (p11_buffer *buffer,
            const char *string,
            size_t length)
{
	unsigned char *data;

	if (length > INT16_MAX) {
		p11_message ("truncating long string");
		length = INT16_MAX;
	}

	data = p11_buffer_append (buffer, 2);
	return_if_fail (data != NULL);
	encode_msb_short (data, length);
	p11_buffer_add (buffer, string, length);
}

static void
convert_alias (const char *input,
            size_t length,
            p11_buffer *buf)
{
	char ch;
	size_t i;

	/*
	 * Java requires that the aliases are 'converted'. For the basic java
	 * cacerts key store this is lower case. We just do this for ASCII, since
	 * we don't want to have to bring in unicode case rules. Since we're
	 * screwing around, we also take out spaces, to make these look like
	 * java aliases.
	 */

	for (i = 0; i < length; i++) {
		ch = input[i];
		if (!isspace (ch) && (ch & 0x80) == 0) {
			ch = tolower (ch);
			p11_buffer_add (buf, &ch, 1);
		}
	}
}

static bool
add_alias (p11_buffer *buffer,
           p11_dict *aliases,
           CK_ATTRIBUTE *label)
{
	const char *input;
	size_t input_len;
	size_t length;
	p11_buffer buf;
	char num[32];
	char *alias;
	int i;

	p11_buffer_init_null (&buf, 64);

	if (label && label->pValue) {
		input = label->pValue;
		input_len = label->ulValueLen;
	} else {
		input = "unlabeled";
		input_len = strlen (input);
	}

	convert_alias (input, input_len, &buf);

	for (i = 0; i < INT32_MAX; i++) {
		if (i > 0) {
			snprintf (num, sizeof (num), "-%d", i);
			p11_buffer_add (&buf, num, -1);
		}

		return_val_if_fail (p11_buffer_ok (&buf), false);
		if (!p11_dict_get (aliases, buf.data)) {
			alias = p11_buffer_steal (&buf, &length);
			if (!p11_dict_set (aliases, alias, alias))
				return_val_if_reached (false);
			add_string (buffer, alias, length);
			return true;
		}

		p11_buffer_reset (&buf, 0);
	}

	return false;
}

static bool
prepare_jks_buffer (p11_enumerate *ex,
                    p11_buffer *buffer)
{
	const unsigned char magic[] = { 0xfe, 0xed, 0xfe, 0xed };
	const int version = 2;
	size_t count_at;
	unsigned char *digest;
	CK_ATTRIBUTE *label;
	p11_dict *aliases;
	size_t length;
	int64_t now;
	int count;
	CK_RV rv;

	enum {
		private_key = 1,
		trusted_cert = 2,
	};

	/*
	 * Documented in the java sources in the file:
	 * src/share/classes/sun/security/provider/JavaKeyStore.java
	 */

	p11_buffer_add (buffer, magic, sizeof (magic));
	add_msb_int (buffer, version);
	count_at = buffer->len;
	p11_buffer_append (buffer, 4);
	count = 0;

	/*
	 * We use the current time for each entry. Java expects the time
	 * when this was this certificate was added to the keystore, however
	 * we don't have that information. Java uses time in milliseconds
	 */
	now = time (NULL);
	return_val_if_fail (now > 0, false);
	now *= 1000; /* seconds to milliseconds */

	/*
	 * The aliases in the output file need to be unique. We use a hash
	 * table to guarantee this.
	 */
	aliases = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, NULL);
	return_val_if_fail (aliases != NULL, false);

	/* For every certificate */
	while ((rv = p11_kit_iter_next (ex->iter)) == CKR_OK) {
		count++;

		/* The type of entry */
		add_msb_int (buffer, trusted_cert);

		/* The alias */
		label = p11_attrs_find_valid (ex->attrs, CKA_LABEL);
		if (!add_alias (buffer, aliases, label)) {
			p11_message ("could not generate a certificate alias name");
			p11_dict_free (aliases);
			return false;
		}

		/* The creation date: current time */
		add_msb_long (buffer, now);

		/* The type of the certificate */
		add_string (buffer, "X.509", 5);

		/* The DER encoding of the certificate */
		add_msb_int (buffer, ex->cert_len);
		p11_buffer_add (buffer, ex->cert_der, ex->cert_len);
	}

	p11_dict_free (aliases);

	if (rv != CKR_OK && rv != CKR_CANCEL) {
		p11_message ("failed to find certificates: %s", p11_kit_strerror (rv));
		return false;
	}

	/* Place the count in the right place */
	encode_msb_int ((unsigned char *)buffer->data + count_at, count);

	/*
	 * Java keystore reinvents HMAC and uses it to try and "secure" the
	 * cacerts. We fill this in and use the default "changeit" string
	 * as the password for this keyed digest.
	 */
	length = buffer->len;
	digest = p11_buffer_append (buffer, P11_DIGEST_SHA1_LEN);
	return_val_if_fail (digest != NULL, false);
	p11_digest_sha1 (digest,
	                 "\000c\000h\000a\000n\000g\000e\000i\000t", (size_t)16, /* default password */
	                 "Mighty Aphrodite", (size_t)16, /* go figure */
	                 buffer->data, length,
	                 NULL);

	return_val_if_fail (p11_buffer_ok (buffer), false);
	return true;
}

bool
p11_extract_jks_cacerts (p11_enumerate *ex,
                         const char *destination)
{
	p11_buffer buffer;
	p11_save_file *file;
	bool ret;

	p11_buffer_init (&buffer, 1024 * 10);
	ret = prepare_jks_buffer (ex, &buffer);
	if (ret) {
		file = p11_save_open_file (destination, NULL, ex->flags);
		ret = p11_save_write_and_finish (file, buffer.data, buffer.len);
	}

	p11_buffer_uninit (&buffer);
	return ret;
}
