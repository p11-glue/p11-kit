/*
 * Copyright (C) 2011 Collabora Ltd.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#define DEBUG_FLAG DEBUG_PIN
#include "debug.h"
#include "hash.h"
#include "pkcs11.h"
#include "p11-kit.h"
#include "pin.h"
#include "private.h"
#include "ptr-array.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * SECTION:p11-pin
 * @title: PIN Callbacks
 * @short_description: PIN Callbacks
 *
 * Applications can register a callback which will be called to provide a password
 * associated with a given pin file.
 * PKCS\#11 URIs can be used in configuration files or applications to represent
 * PKCS\#11 modules, tokens or objects. An example of a URI might be:
 *
 * <code><literallayout>
 *      pkcs11:token=The\%20Software\%20PKCS\#11\%20softtoken;
 *          manufacturer=Snake\%20Oil,\%20Inc.;serial=;object=my-certificate;
 *          model=1.0;objecttype=cert;id=\%69\%95\%3e\%5c\%f4\%bd\%ec\%91
 * </literallayout></code>
 *
 * You can use p11_kit_uri_parse() to parse such a URI, and p11_kit_uri_format()
 * to build one. URIs are represented by the #P11KitUri structure. You can match
 * a parsed URI against PKCS\#11 tokens with p11_kit_uri_match_token_info()
 * or attributes with p11_kit_uri_match_attributes().
 *
 * Since URIs can represent different sorts of things, when parsing or formatting
 * a URI a 'context' can be used to indicate which sort of URI is expected.
 *
 * URIs have an <code>unrecognized</code> flag. This flag is set during parsing
 * if any parts of the URI are not recognized. This may be because the part is
 * from a newer version of the PKCS\#11 spec or because that part was not valid
 * inside of the desired context used when parsing.
 */

/**
 * P11KitUri:
 *
 * A structure representing a PKCS\#11 URI. There are no public fields
 * visible in this structure. Use the various accessor functions.
 */

/**
 * P11KitUriType:
 * @P11_KIT_URI_FOR_OBJECT: The URI represents one or more objects
 * @P11_KIT_URI_FOR_TOKEN: The URI represents one or more tokens
 * @P11_KIT_URI_FOR_MODULE: The URI represents one or more modules
 * @P11_KIT_URI_FOR_MODULE_WITH_VERSION: The URI represents a module with
 *     a specific version.
 * @P11_KIT_URI_FOR_OBJECT_ON_TOKEN: The URI represents one or more objects
 *     that are present on a specific token.
 * @P11_KIT_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE: The URI represents one or more
 *     objects that are present on a specific token, being used with a certain
 *     module.
 * @P11_KIT_URI_FOR_ANY: The URI can represent anything
 *
 * A PKCS\#11 URI can represent different kinds of things. This flag is used by
 * p11_kit_uri_parse() to denote in what context the URI will be used.
 *
 * The various types can be combined.
 */

/**
 * P11KitUriResult:
 * @P11_KIT_URI_OK: Success
 * @P11_KIT_URI_NO_MEMORY: Memory allocation failed
 * @P11_KIT_URI_BAD_SCHEME: The URI had a bad scheme
 * @P11_KIT_URI_BAD_ENCODING: The URI had a bad encoding
 * @P11_KIT_URI_BAD_SYNTAX: The URI had a bad syntax
 * @P11_KIT_URI_BAD_VERSION: The URI contained a bad version number
 * @P11_KIT_URI_NOT_FOUND: A requested part of the URI was not found
 *
 * Error codes returned by various functions. The functions each clearly state
 * which error codes they are capable of returning.
 */

/**
 * P11_KIT_URI_SCHEME:
 *
 * String of URI scheme for PKCS\#11 URIs.
 */

/**
 * P11_KIT_URI_SCHEME_LEN:
 *
 * Length of %P11_KIT_URI_SCHEME.
 */

typedef struct _PinfileCallback {
	/* Only used/modified within the lock */
	int refs;

	/* Readonly after construct */
	p11_kit_pin_callback func;
	void *user_data;
	p11_kit_pin_callback_destroy destroy;
} PinfileCallback;

/*
 * Shared data between threads, protected by the mutex, a structure so
 * we can audit thread safety easier.
 */
static struct _Shared {
	hash_t *pinfiles;
} gl = { NULL };

static void*
ref_pinfile_callback (void *pointer)
{
	PinfileCallback *cb = pointer;
	cb->refs++;
	return pointer;
}

static void
unref_pinfile_callback (void *pointer)
{
	PinfileCallback *cb = pointer;
	assert (cb->refs >= 1);

	cb->refs--;
	if (cb->refs == 0) {
		if (cb->destroy)
			(cb->destroy) (cb->user_data);
		free (cb);
	}
}

int
p11_kit_pin_register_callback (const char *pinfile, p11_kit_pin_callback callback,
                               void *callback_data, p11_kit_pin_callback_destroy callback_destroy)
{
	PinfileCallback *cb;
	ptr_array_t *callbacks;
	char *name;
	int ret;

	cb = calloc (1, sizeof (PinfileCallback));
	if (cb == NULL) {
		errno = ENOMEM;
		return -1;
	}

	name = strdup (pinfile);
	if (name == NULL) {
		free (cb);
		errno = ENOMEM;
		return -1;
	}

	cb->refs = 1;
	cb->func = callback;
	cb->user_data = callback_data;
	cb->destroy = callback_destroy;

	_p11_lock ();

		if (gl.pinfiles == NULL) {
			gl.pinfiles = hash_create (hash_string_hash, hash_string_equal,
			                           free, (hash_destroy_func)ptr_array_free);
			if (gl.pinfiles == NULL) {
				errno = ENOMEM;
				ret = -1;
			}
		}

		if (gl.pinfiles != NULL)
			callbacks = hash_get (gl.pinfiles, pinfile);

		if (callbacks == NULL) {
			callbacks = ptr_array_create (unref_pinfile_callback);
			if (callbacks == NULL) {
				errno = ENOMEM;
				ret = -1;
			} else if (!hash_set (gl.pinfiles, name, callbacks)) {
				ptr_array_free (callbacks);
				callbacks = NULL;
				errno = ENOMEM;
				ret = -1;
			} else {
				/* Note that we've consumed the name */
				name = NULL;
			}
		}

		if (callbacks != NULL) {
			if (ptr_array_add (callbacks, cb) < 0) {
				errno = ENOMEM;
				ret = -1;
			} else {
				/* Note that we've consumed the callback */
				cb = NULL;
			}
		}

	_p11_unlock ();

	/* Unless consumed above */
	free (name);
	if (cb != NULL)
		unref_pinfile_callback (cb);

	return ret;
}

void
p11_kit_pin_unregister_callback (const char *pinfile, p11_kit_pin_callback callback,
                                 void *callback_data)
{
	PinfileCallback *cb;
	ptr_array_t *callbacks;
	unsigned int i;

	_p11_lock ();

		if (gl.pinfiles) {
			callbacks = hash_get (gl.pinfiles, pinfile);
			if (callbacks) {
				for (i = 0; i < ptr_array_count (callbacks); i++) {
					cb = ptr_array_at (callbacks, i);
					if (cb->func == callback && cb->user_data == callback_data) {
						ptr_array_remove (callbacks, i);
						break;
					}
				}

				if (ptr_array_count (callbacks) == 0)
					hash_remove (gl.pinfiles, pinfile);
			}

			/* When there are no more pinfiles, get rid of the hash table */
			if (hash_count (gl.pinfiles) == 0) {
				hash_free (gl.pinfiles);
				gl.pinfiles = NULL;
			}
		}

	_p11_unlock ();
}

int
p11_kit_pin_read_pinfile (const char *pinfile, P11KitUri *pin_uri,
                          const char *pin_description, P11KitPinFlags flags,
                          char *pin, size_t pin_max)
{
	PinfileCallback **snapshot = NULL;
	unsigned int snapshot_count = 0;
	ptr_array_t *callbacks;
	unsigned int i;
	int ret;

	_p11_lock ();

		/* Find and ref the pinfile data */
		if (gl.pinfiles) {
			callbacks = hash_get (gl.pinfiles, pinfile);

			/* If we didn't find any snapshots try the global ones */
			if (callbacks == NULL)
				callbacks = hash_get (gl.pinfiles, P11_KIT_PIN_FALLBACK);

			if (callbacks != NULL) {
				snapshot = (PinfileCallback**)ptr_array_snapshot (callbacks);
				snapshot_count = ptr_array_count (callbacks);
				for (i = 0; i < snapshot_count; i++)
					ref_pinfile_callback (snapshot[i]);
			}
		}

	_p11_unlock ();

	if (snapshot == NULL)
		return 0;

	for (i = 0; i < snapshot_count; i++) {
		ret = (snapshot[i]->func) (pinfile, pin_uri, pin_description, flags,
		                           snapshot[i]->user_data, pin, pin_max);
	}

	_p11_lock ();
		for (i = 0; i < snapshot_count; i++)
			unref_pinfile_callback (snapshot[i]);
		free (snapshot);
	_p11_unlock ();

	return ret;
}
