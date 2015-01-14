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

#include "asn1.h"
#include "attrs.h"
#include "buffer.h"
#include "compat.h"
#include "debug.h"
#include "dict.h"
#include "digest.h"
#include "extract.h"
#include "message.h"
#include "oid.h"
#include "path.h"
#include "pem.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "save.h"
#include "utf8.h"
#include "x509.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* These functions are declared with a global scope for testing */

void        p11_openssl_canon_string           (char *str,
                                                size_t *len);

bool        p11_openssl_canon_string_der       (p11_buffer *der);

bool        p11_openssl_canon_name_der         (p11_dict *asn1_defs,
                                                p11_buffer *der);

static p11_array *
empty_usages (void)
{
	return p11_array_new (free);
}

static bool
known_usages (p11_array *oids)
{
	char *string;
	int i;

	static const char *const strings[] = {
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

	for (i = 0; strings[i] != NULL; i++) {
		string = strdup (strings[i]);
		return_val_if_fail (string != NULL, false);
		if (!p11_array_push (oids, string))
			return_val_if_reached (false);
	}

	return true;
}

static bool
load_usage_ext (p11_enumerate *ex,
                const unsigned char *ext_oid,
                p11_array **oids)
{
	unsigned char *value;
	node_asn *ext = NULL;
	size_t length;

	if (ex->attached)
		ext = p11_dict_get (ex->attached, ext_oid);
	if (ext == NULL) {
		*oids = NULL;
		return true;
	}

	value = p11_asn1_read (ext, "extnValue", &length);
	return_val_if_fail (value != NULL, false);

	*oids = p11_x509_parse_extended_key_usage (ex->asn1_defs, value, length);
	return_val_if_fail (*oids != NULL, false);

	free (value);
	return true;
}

static bool
write_usages (node_asn *asn,
              const char *field,
              p11_array *oids)
{
	char *last;
	int ret;
	int i;

	/*
	 * No oids? Then doing this will make the entire optional
	 * field go away
	 */
	if (oids == NULL) {
		ret = asn1_write_value (asn, field, NULL, 0);
		return_val_if_fail (ret == ASN1_SUCCESS, false);

	} else {
		if (asprintf (&last, "%s.?LAST", field) < 0)
			return_val_if_reached (false);
		for (i = 0; i < oids->num; i++) {
			ret = asn1_write_value (asn, field, "NEW", 1);
			return_val_if_fail (ret == ASN1_SUCCESS, false);
			ret = asn1_write_value (asn, last, oids->elem[i], -1);
			return_val_if_fail (ret == ASN1_SUCCESS, false);
		}

		free (last);
	}

	return true;
}

static bool
write_trust_and_rejects (p11_enumerate *ex,
                         node_asn *asn)
{
	p11_array *trusts = NULL;
	p11_array *rejects = NULL;
	CK_BBOOL trust;
	CK_BBOOL distrust;

	if (!p11_attrs_find_bool (ex->attrs, CKA_TRUSTED, &trust))
		trust = CK_FALSE;
	if (!p11_attrs_find_bool (ex->attrs, CKA_X_DISTRUSTED, &distrust))
		distrust = CK_FALSE;

	if (!load_usage_ext (ex, P11_OID_OPENSSL_REJECT, &rejects))
		return_val_if_reached (false);

	if (distrust) {

		/*
		 * If this is on the blacklist then, make sure we have
		 * an empty trusts field and add as many things to rejects
		 * as possible.
		 */
		trusts = NULL;

		if (!rejects)
			rejects = empty_usages ();
		if (!known_usages (rejects))
			return_val_if_reached (false);
		return_val_if_fail (rejects != NULL, false);

	} else if (trust) {

		/*
		 * If this is an anchor, then try and guarantee that there
		 * are some trust anchors.
		 */

		if (!load_usage_ext (ex, P11_OID_EXTENDED_KEY_USAGE, &trusts))
			return_val_if_reached (false);

	} else {

		/*
		 * This is not an anchor, always put an empty trusts
		 * section, with possible rejects, loaded above
		 */

		trusts = empty_usages ();
	}

	if (!write_usages (asn, "trust", trusts) ||
	    !write_usages (asn, "reject", rejects))
		return_val_if_reached (false);

	p11_array_free (trusts);
	p11_array_free (rejects);
	return true;
}

static bool
write_keyid (p11_enumerate *ex,
             node_asn *asn)
{
	unsigned char *value = NULL;
	node_asn *ext = NULL;
	size_t length = 0;
	int ret;

	if (ex->attached)
		ext = p11_dict_get (ex->attached, P11_OID_SUBJECT_KEY_IDENTIFIER);
	if (ext != NULL) {
		value = p11_asn1_read (ext, "extnValue", &length);
		return_val_if_fail (value != NULL, false);
	}

	ret = asn1_write_value (asn, "keyid", value, length);
	return_val_if_fail (ret == ASN1_SUCCESS, false);
	free (value);

	return true;
}

static bool
write_alias (p11_enumerate *ex,
             node_asn *asn)
{
	CK_ATTRIBUTE *label;
	int ret;

	label = p11_attrs_find_valid (ex->attrs, CKA_LABEL);
	if (label == NULL) {
		ret = asn1_write_value (asn, "alias", NULL, 0);
		return_val_if_fail (ret == ASN1_SUCCESS, false);
	} else {
		ret = asn1_write_value (asn, "alias", label->pValue, label->ulValueLen);
		return_val_if_fail (ret == ASN1_SUCCESS, false);
	}

	return true;
}

static bool
write_other (p11_enumerate *ex,
             node_asn *asn)
{
	int ret;

	ret = asn1_write_value (asn, "other", NULL, 0);
	return_val_if_fail (ret == ASN1_SUCCESS, false);

	return true;
}

static bool
prepare_pem_contents (p11_enumerate *ex,
                      p11_buffer *buffer)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	unsigned char *der;
	node_asn *asn;
	size_t offset;
	int ret;
	int len;

	p11_buffer_add (buffer, ex->cert_der, ex->cert_len);

	asn = p11_asn1_create (ex->asn1_defs, "OPENSSL.CertAux");
	return_val_if_fail (asn != NULL, false);

	if (!write_trust_and_rejects (ex, asn) ||
	    !write_alias (ex, asn) ||
	    !write_keyid (ex, asn) ||
	    !write_other (ex, asn))
		return_val_if_reached (false);

	len = 0;
	offset = buffer->len;

	ret = asn1_der_coding (asn, "", NULL, &len, message);
	return_val_if_fail (ret == ASN1_MEM_ERROR, false);

	der = p11_buffer_append (buffer, len);
	return_val_if_fail (der != NULL, false);

	ret = asn1_der_coding (asn, "", der, &len, message);
	return_val_if_fail (ret == ASN1_SUCCESS, false);

	buffer->len = offset + len;
	asn1_delete_structure (&asn);
	return true;
}

bool
p11_extract_openssl_bundle (p11_enumerate *ex,
                            const char *destination)
{
	p11_save_file *file;
	p11_buffer output;
	p11_buffer buf;
	char *comment;
	bool ret = true;
	bool first;
	CK_RV rv;

	file = p11_save_open_file (destination, NULL, ex->flags);
	if (!file)
		return false;

	first = true;
	p11_buffer_init (&output, 0);
	while ((rv = p11_kit_iter_next (ex->iter)) == CKR_OK) {
		p11_buffer_init (&buf, 1024);
		if (!p11_buffer_reset (&output, 2048))
			return_val_if_reached (false);

		if (prepare_pem_contents (ex, &buf)) {
			if (!p11_pem_write (buf.data, buf.len, "TRUSTED CERTIFICATE", &output))
				return_val_if_reached (false);

			comment = p11_enumerate_comment (ex, first);
			first = false;

			ret = p11_save_write (file, comment, -1) &&
			      p11_save_write (file, output.data, output.len);

			free (comment);
		}

		p11_buffer_uninit (&buf);

		if (!ret)
			break;
	}

	p11_buffer_uninit (&output);

	if (rv != CKR_OK && rv != CKR_CANCEL) {
		p11_message ("failed to find certificates: %s", p11_kit_strerror (rv));
		ret = false;
	}

	/*
	 * This will produce an empty file (which is a valid PEM bundle) if no
	 * certificates were found.
	 */

	if (!p11_save_finish_file (file, NULL, ret))
		ret = false;
	return ret;
}

void
p11_openssl_canon_string (char *str,
                          size_t *len)
{
	bool nsp;
	bool sp;
	char *in;
	char *out;
	char *end;

	/*
	 * Now that the string is UTF-8 here we convert the string to the
	 * OpenSSL canonical form. This is a bit odd and openssl specific.
	 * Basically they ignore any char over 127, do ascii tolower() stuff
	 * and collapse spaces based on isspace().
	 */

	for (in = out = str, end = out + *len, sp = false, nsp = false; in < end; in++) {
		if (*in & 0x80 || !isspace (*in)) {
			/* If there has been a space, then add one */
			if (sp)
				*out++ = ' ';
			*out++ = (*in & 0x80) ? *in : tolower (*in);
			sp = false;
			nsp = true;
		/* If there has been a non-space, then note we should get one */
		} else if (nsp) {
			nsp = false;
			sp = true;
		}
	}

	if (out < end)
		out[0] = 0;
	*len = out - str;
}

bool
p11_openssl_canon_string_der (p11_buffer *der)
{
	char *string;
	size_t length;
	int output_len;
	int len_len;
	bool unknown_string;
	unsigned char *output;
	int len;

	string = p11_x509_parse_directory_string (der->data, der->len, &unknown_string, &length);

	/* Just pass through all the non-string types */
	if (string == NULL)
		return unknown_string;

	p11_openssl_canon_string (string, &length);

	asn1_length_der (length, NULL, &len_len);
	output_len = 1 + len_len + length;

	if (!p11_buffer_reset (der, output_len))
		return_val_if_reached (false);

	output = der->data;
	der->len = output_len;

	output[0] = 12; /* UTF8String */
	len = output_len - 1;
	asn1_octet_der ((unsigned char *)string, length, output + 1, &len);
	assert (len == output_len - 1);

	free (string);
	return true;
}

bool
p11_openssl_canon_name_der (p11_dict *asn1_defs,
                            p11_buffer *der)
{
	p11_buffer value;
	char outer[64];
	char field[64];
	node_asn *name;
	void *at;
	int value_len;
	bool failed;
	size_t offset;
	int ret;
	int num;
	int len;
	int i, j;

	name = p11_asn1_decode (asn1_defs, "PKIX1.Name", der->data, der->len, NULL);
	return_val_if_fail (name != NULL, false);

	ret = asn1_number_of_elements (name, "rdnSequence", &num);
	return_val_if_fail (ret == ASN1_SUCCESS, false);

	p11_buffer_init (&value, 0);
	p11_buffer_reset (der, 0);

	for (i = 1, failed = false; !failed && i < num + 1; i++) {
		snprintf (outer, sizeof (outer), "rdnSequence.?%d", i);
		for (j = 1; !failed; j++) {
			snprintf (field, sizeof (field), "%s.?%d.value", outer, j);

			value_len = 0;
			ret = asn1_read_value (name, field, NULL, &value_len);
			if (ret == ASN1_ELEMENT_NOT_FOUND)
				break;

			return_val_if_fail (ret == ASN1_MEM_ERROR, false);

			if (!p11_buffer_reset (&value, value_len))
				return_val_if_reached (false);

			ret = asn1_read_value (name, field, value.data, &value_len);
			return_val_if_fail (ret == ASN1_SUCCESS, false);
			value.len = value_len;

			if (p11_openssl_canon_string_der (&value)) {
				ret = asn1_write_value (name, field, value.data, value.len);
				return_val_if_fail (ret == ASN1_SUCCESS, false);
			} else {
				failed = true;
			}
		}

		/*
		 * Yes the OpenSSL canon strangeness, is a concatenation
		 * of all the RelativeDistinguishedName DER encodings, without
		 * an outside wrapper.
		 */
		if (!failed) {
			len = -1;
			ret = asn1_der_coding (name, outer, NULL, &len, NULL);
			return_val_if_fail (ret == ASN1_MEM_ERROR, false);

			offset = der->len;
			at = p11_buffer_append (der, len);
			return_val_if_fail (at != NULL, false);

			ret = asn1_der_coding (name, outer, at, &len, NULL);
			return_val_if_fail (ret == ASN1_SUCCESS, false);
			der->len = offset + len;
		}
	}

	asn1_delete_structure (&name);
	p11_buffer_uninit (&value);
	return !failed;
}

#ifdef OS_UNIX

static char *
symlink_for_subject_hash (p11_enumerate *ex)
{
	unsigned char md[P11_DIGEST_SHA1_LEN];
	p11_buffer der;
	CK_ATTRIBUTE *subject;
	unsigned long hash;
	char *linkname = NULL;

	subject = p11_attrs_find_valid (ex->attrs, CKA_SUBJECT);
	if (!subject || !subject->pValue || !subject->ulValueLen)
		return NULL;

	p11_buffer_init_full (&der, memdup (subject->pValue, subject->ulValueLen),
	                      subject->ulValueLen, 0, realloc, free);
	return_val_if_fail (der.data != NULL, NULL);

	if (p11_openssl_canon_name_der (ex->asn1_defs, &der)) {
		p11_digest_sha1 (md, der.data, der.len, NULL);

		hash = (
		        ((unsigned long)md[0]       ) | ((unsigned long)md[1] << 8L) |
		        ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)
		) & 0xffffffffL;

		if (asprintf (&linkname, "%08lx", hash) < 0)
			return_val_if_reached (NULL);
	}

	p11_buffer_uninit (&der);
	return linkname;
}

static char *
symlink_for_subject_old_hash (p11_enumerate *ex)
{
	unsigned char md[P11_DIGEST_MD5_LEN];
	CK_ATTRIBUTE *subject;
	unsigned long hash;
	char *linkname;

	subject = p11_attrs_find_valid (ex->attrs, CKA_SUBJECT);
	if (!subject)
		return NULL;

	p11_digest_md5 (md, subject->pValue, (size_t)subject->ulValueLen, NULL);

	hash = (
	         ((unsigned long)md[0]       ) | ((unsigned long)md[1] << 8L) |
	         ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)
	       ) & 0xffffffffL;

	if (asprintf (&linkname, "%08lx", hash) < 0)
		return_val_if_reached (NULL);

	return linkname;
}

#endif /* OS_UNIX */

/*
 * The OpenSSL style c_rehash stuff
 *
 * Different versions of openssl build these hashes differently
 * so output both of them. Shouldn't cause confusion, because
 * multiple certificates can hash to the same link anyway,
 * and this is the reason for the trailing number after the dot.
 *
 * The trailing number is incremented p11_save_symlink_in() if it
 * conflicts with something we've already written out.
 *
 * On Windows no symlinks.
 */
bool
p11_openssl_symlink (p11_enumerate *ex,
                     p11_save_dir *dir,
                     const char *filename)
{
	bool ret = true;
#ifdef OS_UNIX
	char *linkname;

	linkname = symlink_for_subject_hash (ex);
	if (linkname) {
		ret = p11_save_symlink_in (dir, linkname, ".0", filename);
		free (linkname);
	}

	if (ret) {
		linkname = symlink_for_subject_old_hash (ex);
		if (linkname) {
			ret = p11_save_symlink_in (dir, linkname, ".0", filename);
			free (linkname);
		}
	}
#endif /* OS_UNIX */
	return ret;
}

bool
p11_extract_openssl_directory (p11_enumerate *ex,
                               const char *destination)
{
	char *filename;
	p11_save_file *file;
	p11_save_dir *dir;
	p11_buffer output;
	p11_buffer buf;
	bool ret = true;
	char *path;
	char *name;
	CK_RV rv;

	dir = p11_save_open_directory (destination, ex->flags);
	if (dir == NULL)
		return false;

	p11_buffer_init (&buf, 0);
	p11_buffer_init (&output, 0);

	while ((rv = p11_kit_iter_next (ex->iter)) == CKR_OK) {
		if (!p11_buffer_reset (&buf, 1024))
			return_val_if_reached (false);
		if (!p11_buffer_reset (&output, 2048))
			return_val_if_reached (false);

		if (prepare_pem_contents (ex, &buf)) {
			if (!p11_pem_write (buf.data, buf.len, "TRUSTED CERTIFICATE", &output))
				return_val_if_reached (false);

			name = p11_enumerate_filename (ex);
			return_val_if_fail (name != NULL, false);

			filename = NULL;
			path = NULL;
			ret = false;

			file = p11_save_open_file_in (dir, name, ".pem");
			if (file != NULL) {
				ret = p11_save_write (file, output.data, output.len);
				if (!p11_save_finish_file (file, &path, ret))
					ret = false;
				if (ret)
					filename = p11_path_base (path);
			}
			ret = p11_openssl_symlink(ex, dir, filename);

			free (filename);
			free (path);
			free (name);
		}

		if (!ret)
			break;
	}

	p11_buffer_uninit (&buf);
	p11_buffer_uninit (&output);

	if (rv != CKR_OK && rv != CKR_CANCEL) {
		p11_message ("failed to find certificates: %s", p11_kit_strerror (rv));
		ret = false;
	}

	p11_save_finish_directory (dir, ret);
	return ret;
}
