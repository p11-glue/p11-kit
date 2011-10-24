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
#include "hashmap.h"
#include "pkcs11.h"
#include "p11-kit.h"
#include "pin.h"
#include "private.h"
#include "ptr-array.h"
#include "util.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * SECTION:p11-kit-pin
 * @title: PIN Callbacks
 * @short_description: PIN Callbacks
 *
 * Applications can register a callback which will be called to provide a
 * password associated with a given pin file.
 *
 * PKCS\#11 URIs can contain a 'pin-source' attribute. The value of this attribute
 * is application dependent, but often references a file containing a PIN to
 * use.
 *
 * Using these functions, an applications or libraries can register a
 * callback with p11_kit_pin_register_callback() to be called when a given
 * 'pin-source' attribute value is requested. The application can then prompt
 * the user or retrieve a PIN for the given context. These registered
 * callbacks are only relevant and valid within the current process.
 *
 * A fallback callback can be registered by passing the %P11_KIT_PIN_FALLBACK
 * value to p11_kit_pin_register_callback(). This fallback callback will be
 * called for every 'pin-source' attribute request for which no callback has been
 * directly registered.
 *
 * To request a PIN for a given 'pin-source' attribute, use the
 * p11_kit_pin_request() function. If this function returns %NULL then either
 * no callbacks were registered or none of them could handle the request.
 *
 * If multiple callbacks are registered for the same PIN source, then they are
 * called in last-registered-first-called order. They are called in turn until
 * one of them can handle the request. Fallback callbacks are not called if
 * a callback was registered specifically for a requested 'pin-source' attribute.
 *
 * PINs themselves are handled inside of P11KitPin structures. These are thread
 * safe and allow the callback to specify how the PIN is stored in memory
 * and freed. A callback can use p11_kit_pin_new_for_string() or related
 * functions to create a PIN to be returned.
 *
 * For example in order to handle the following PKCS\#11 URI with a 'pin-source'
 * attribute
 *
 * <code><literallayout>
 *      pkcs11:id=\%69\%95\%3e\%5c\%f4\%bd\%ec\%91;pin-source=my-application
 * </literallayout></code>
 *
 * an application could register a callback like this:
 *
 * <informalexample><programlisting>
 * static P11KitPin*
 * my_application_pin_callback (const char *pin_source, P11KitUri *pin_uri,
 *                              const char *pin_description, P11KitPinFlags pin_flags,
 *                              void *callback_data)
 * {
 *     return p11_kit_pin_new_from_string ("pin-value");
 * }
 *
 * p11_kit_pin_register_callback ("my-application", my_application_pin_callback,
 *                                NULL, NULL);
 * </programlisting></informalexample>
 */

/**
 * P11KitPinFlags:
 * @P11_KIT_PIN_FLAGS_USER_LOGIN: The PIN is for a PKCS\#11 user type login.
 * @P11_KIT_PIN_FLAGS_SO_LOGIN: The PIN is for a PKCS\#11 security officer type login.
 * @P11_KIT_PIN_FLAGS_CONTEXT_LOGIN: The PIN is for a PKCS\#11 contect specific type login.
 * @P11_KIT_PIN_FLAGS_RETRY: The PIN is being requested again, due to an invalid previous PIN.
 * @P11_KIT_PIN_FLAGS_MANY_TRIES: The PIN has failed too many times, and few tries are left.
 * @P11_KIT_PIN_FLAGS_FINAL_TRY: The PIN has failed too many times, and this is the last try.
 *
 * Flags that are passed to p11_kit_pin_request() and registered callbacks.
 */

/**
 * P11_KIT_PIN_FALLBACK:
 *
 * Used with p11_kit_pin_register_callback() to register a fallback callback.
 * This callback will be called if no other
 * String of URI scheme for PKCS\#11 URIs.
 */

typedef struct _PinCallback {
	/* Only used/modified within the lock */
	int refs;

	/* Readonly after construct */
	p11_kit_pin_callback func;
	void *user_data;
	p11_kit_pin_destroy_func destroy;
} PinCallback;

/*
 * Shared data between threads, protected by the mutex, a structure so
 * we can audit thread safety easier.
 */
static struct _Shared {
	hashmap *pin_sources;
} gl = { NULL };

static void*
ref_pin_callback (void *pointer)
{
	PinCallback *cb = pointer;
	cb->refs++;
	return pointer;
}

static void
unref_pin_callback (void *pointer)
{
	PinCallback *cb = pointer;
	assert (cb->refs >= 1);

	cb->refs--;
	if (cb->refs == 0) {
		if (cb->destroy)
			(cb->destroy) (cb->user_data);
		free (cb);
	}
}

/**
 * p11_kit_pin_register_callback:
 * @pin_source: the 'pin-source' attribute this this callback is for
 * @callback: the callback function
 * @callback_data: data that will be passed to the callback
 * @callback_destroy: a function that will be called with @callback_data when
 *     the callback is unregistered.
 *
 * Register a callback to handle PIN requests for a given 'pin-source' attribute.
 * If @pin_source is set to P11_KIT_PIN_FALLBACK then this will be a fallback
 * callback and will be called for requests for which no other callback has
 * been specifically registered.
 *
 * If multiple callbacks are registered for the same @pin_source value, then
 * the last registered callback will be the first to be called.
 *
 * Returns: Returns negative if registering fails. This can only happen if
 *     memory cannot be allocated.
 */
int
p11_kit_pin_register_callback (const char *pin_source, p11_kit_pin_callback callback,
                               void *callback_data, p11_kit_pin_destroy_func callback_destroy)
{
	ptr_array_t *callbacks = NULL;
	PinCallback *cb;
	char *name;
	int ret;

	cb = calloc (1, sizeof (PinCallback));
	if (cb == NULL) {
		errno = ENOMEM;
		return -1;
	}

	name = strdup (pin_source);
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

		if (gl.pin_sources == NULL) {
			gl.pin_sources = _p11_hash_create (_p11_hash_string_hash, _p11_hash_string_equal,
			                                   free, (hash_destroy_func)_p11_ptr_array_free);
			if (gl.pin_sources == NULL) {
				errno = ENOMEM;
				ret = -1;
			}
		}

		if (gl.pin_sources != NULL)
			callbacks = _p11_hash_get (gl.pin_sources, pin_source);

		if (callbacks == NULL) {
			callbacks = _p11_ptr_array_create (unref_pin_callback);
			if (callbacks == NULL) {
				errno = ENOMEM;
				ret = -1;
			} else if (!_p11_hash_set (gl.pin_sources, name, callbacks)) {
				_p11_ptr_array_free (callbacks);
				callbacks = NULL;
				errno = ENOMEM;
				ret = -1;
			} else {
				/* Note that we've consumed the name */
				name = NULL;
			}
		}

		if (callbacks != NULL) {
			if (_p11_ptr_array_add (callbacks, cb) < 0) {
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
		unref_pin_callback (cb);

	return ret;
}

/**
 * p11_kit_pin_unregister_callback:
 * @pin_source: the 'pin-source' attribute the callback was registered for
 * @callback: the callback function that was registered
 * @callback_data: data that was registered for the callback
 *
 * Unregister a callback that was previously registered with the
 * p11_kit_pin_register_callback() function. If more than one registered
 * callback matches the given arguments, then only one of those will be
 * removed.
 */
void
p11_kit_pin_unregister_callback (const char *pin_source, p11_kit_pin_callback callback,
                                 void *callback_data)
{
	PinCallback *cb;
	ptr_array_t *callbacks;
	unsigned int i;

	_p11_lock ();

		if (gl.pin_sources) {
			callbacks = _p11_hash_get (gl.pin_sources, pin_source);
			if (callbacks) {
				for (i = 0; i < _p11_ptr_array_count (callbacks); i++) {
					cb = _p11_ptr_array_at (callbacks, i);
					if (cb->func == callback && cb->user_data == callback_data) {
						_p11_ptr_array_remove (callbacks, i);
						break;
					}
				}

				if (_p11_ptr_array_count (callbacks) == 0)
					_p11_hash_remove (gl.pin_sources, pin_source);
			}

			/* When there are no more pin sources, get rid of the hash table */
			if (_p11_hash_size (gl.pin_sources) == 0) {
				_p11_hash_free (gl.pin_sources);
				gl.pin_sources = NULL;
			}
		}

	_p11_unlock ();
}

/**
 * p11_kit_pin_request:
 * @pin_source: the 'pin-source' attribute that is being requested
 * @pin_uri: a PKCS\#11 URI that the PIN is being requested for, optionally %NULL.
 * @pin_description: a description of what the PIN is for, must not be %NULL.
 * @pin_flags: various flags for this request
 *
 * Request a PIN for a given 'pin-source' attribute. The result depends on the
 * registered callbacks.
 *
 * If not %NULL, then the @pin_uri attribute should point to the thing that the
 * PIN is being requested for. In most use cases this should be a PKCS\#11 URI
 * pointing to a token.
 *
 * The @pin_description should always be specified. It is a string describing
 * what the PIN is for. For example this would be the token label, if the PIN
 * is for a token.
 *
 * If more than one callback is registered for the @pin_source, then the latest
 * registered one will be called first. If that callback does not return a
 * PIN, then the next will be called in turn.
 *
 * If no callback is registered for @pin_source, then the fallback callbacks will
 * be invoked in the same way. The fallback callbacks will not be called if any
 * callback has been registered specifically for @pin_source.
 *
 * The PIN returned should be released with p11_kit_pin_unref().
 *
 * Returns: the PIN which should be released with p11_kit_pin_unref(), or %NULL
 *     if no callback was registered or could proivde a PIN
 */
P11KitPin*
p11_kit_pin_request (const char *pin_source, P11KitUri *pin_uri,
                     const char *pin_description, P11KitPinFlags pin_flags)
{
	PinCallback **snapshot = NULL;
	unsigned int snapshot_count = 0;
	ptr_array_t *callbacks;
	P11KitPin *pin;
	unsigned int i;

	_p11_lock ();

		/* Find and ref the pin source data */
		if (gl.pin_sources) {
			callbacks = _p11_hash_get (gl.pin_sources, pin_source);

			/* If we didn't find any snapshots try the global ones */
			if (callbacks == NULL)
				callbacks = _p11_hash_get (gl.pin_sources, P11_KIT_PIN_FALLBACK);

			if (callbacks != NULL) {
				snapshot = (PinCallback**)_p11_ptr_array_snapshot (callbacks);
				snapshot_count = _p11_ptr_array_count (callbacks);
				for (i = 0; i < snapshot_count; i++)
					ref_pin_callback (snapshot[i]);
			}
		}

	_p11_unlock ();

	if (snapshot == NULL)
		return NULL;

	for (pin = NULL, i = snapshot_count; pin == NULL && i > 0; i--) {
		pin = (snapshot[i - 1]->func) (pin_source, pin_uri, pin_description, pin_flags,
		                               snapshot[i - 1]->user_data);
	}

	_p11_lock ();
		for (i = 0; i < snapshot_count; i++)
			unref_pin_callback (snapshot[i]);
		free (snapshot);
	_p11_unlock ();

	return pin;
}

/**
 * p11_kit_pin_callback:
 * @pin_source: a 'pin-source' attribute string
 * @pin_uri: a PKCS\#11 URI that the PIN is for, or %NULL
 * @pin_description: a descrption of what the PIN is for
 * @pin_flags: flags describing the PIN request
 * @callback_data: data that was provided when registering this callback
 *
 * Represents a PIN callback function.
 *
 * The various arguments are the same as the ones passed to
 * p11_kit_pin_request(). The @callback_data argument was the one passed to
 * p11_kit_pin_register_callback() when registering this callback.
 *
 * The function should return %NULL if it could not provide a PIN, either
 * because of an error or a user cancellation.
 *
 * If a PIN is returned, it will be unreferenced by the caller. So it should be
 * either newly allocated, or referenced before returning.
 *
 * Returns: A PIN or %NULL
 */

/**
 * p11_kit_pin_destroy_func:
 * @data: the data to destroy
 *
 * A function called to free or cleanup @data.
 */

/**
 * p11_kit_pin_file_callback:
 * @pin_source: a 'pin-source' attribute string
 * @pin_uri: a PKCS\#11 URI that the PIN is for, or %NULL
 * @pin_description: a descrption of what the PIN is for
 * @pin_flags: flags describing the PIN request
 * @callback_data: unused, should be %NULL
 *
 * This is a PIN callback function that looks up the 'pin-source' attribute in
 * a file with that name. This can be used to enable the normal PKCS\#11 URI
 * behavior described in the RFC.
 *
 * This callback is not registered by default. To register it use code like
 * the following:
 *
 * <informalexample><programlisting>
 * p11_kit_pin_register_callback (P11_KIT_PIN_FALLBACK, p11_kit_pin_file_callback,
 *                                NULL, NULL);
 * </programlisting></informalexample>
 *
 * Returns: A referenced PIN with the pinfile contents, or %NULL if the file
 *    could not be read.
 */
P11KitPin*
p11_kit_pin_file_callback (const char *pin_source,
                           P11KitUri *pin_uri,
                           const char *pin_description,
                           P11KitPinFlags pin_flags,
                           void *callback_data)
{
	unsigned char *buffer;
	size_t used, allocated;
	int error = 0;
	int fd;
	int res;

	/* We don't support retries */
	if (pin_flags & P11_KIT_PIN_FLAGS_RETRY)
		return NULL;

	fd = open (pin_source, O_RDONLY);
	if (fd == -1)
		return NULL;

	buffer = NULL;
	used = 0;
	allocated = 0;

	for (;;) {
		if (used + 256 > allocated) {
			buffer = _p11_realloc (buffer, used + 1024);
			if (buffer == NULL) {
				error = ENOMEM;
				break;
			}
			allocated = used + 1024;
		}

		res = read (fd, buffer + used, allocated - used);
		if (res < 0) {
			if (errno == EAGAIN)
				continue;
			error = errno;
			free (buffer);
			buffer = NULL;
			error = errno;
			break;
		} else if (res == 0) {
			break;
		} else {
			used += res;
		}
	}

	if (buffer == NULL) {
		errno = error;
		return NULL;
	}

	return p11_kit_pin_new_for_buffer (buffer, used, free);
}

/**
 * P11KitPin:
 *
 * A structure representing a PKCS\#11 PIN. There are no public fields
 * visible in this structure. Use the various accessor functions.
 */
struct p11_kit_pin {
	int ref_count;
	unsigned char *buffer;
	size_t length;
	p11_kit_pin_destroy_func destroy;
};

/**
 * p11_kit_pin_new:
 * @value: the value of the PIN
 * @length: the length of @value
 *
 * Create a new P11KitPin with the given PIN value. The exactly @length bytes
 * from @value are used. Null terminated strings, or encodings are not
 * considered.
 *
 * A copy of the @value will be made.
 *
 * Returns: The newly allocated P11KitPin, which should be freed with
 *     p11_kit_pin_unref() when no longer needed.
 */
P11KitPin*
p11_kit_pin_new (const unsigned char *value, size_t length)
{
	unsigned char *copy;
	P11KitPin *pin;

	copy = malloc (length);
	if (copy == NULL)
		return NULL;

	memcpy (copy, value, length);
	pin = p11_kit_pin_new_for_buffer (copy, length, free);
	if (pin == NULL)
		free (copy);
	return pin;
}

/**
 * p11_kit_pin_new_for_string:
 * @value: the value of the PIN
 *
 * Create a new P11KitPin for the given null-terminated string, such as a
 * password. The PIN will consist of the string not including the null terminator.
 * String encoding is not considered.
 *
 * A copy of the @value will be made.
 *
 * Returns: The newly allocated P11KitPin, which should be freed with
 *     p11_kit_pin_unref() when no longer needed.
 */
P11KitPin*
p11_kit_pin_new_for_string (const char *value)
{
	return p11_kit_pin_new ((const unsigned char *)value, strlen (value));
}

/**
 * p11_kit_pin_new_for_buffer:
 * @buffer: the value of the PIN
 * @length: the length of @buffer
 * @destroy: if not %NULL, then called when PIN is destroyed.
 *
 * Create a new P11KitPin which will use @buffer for the PIN value. The buffer
 * will not be copied. String encodings and null characters are not considered.
 *
 * When the last reference to this PIN is lost, then the @destroy callback
 * function will be called passing @buffer as an argument. This allows the
 * caller to use a buffer as a PIN without copying it.
 *
 * <informalexample><programlisting>
 * char *buffer = malloc (128);
 * P11KitPin *pin;
 *  ....
 * pin = p11_kit_pin_new_for_buffer (buffer, 128, free);
 * </programlisting></informalexample>
 *
 * Returns: The newly allocated P11KitPin, which should be freed with
 *     p11_kit_pin_unref() when no longer needed.
 */
P11KitPin*
p11_kit_pin_new_for_buffer (unsigned char *buffer, size_t length,
                            p11_kit_pin_destroy_func destroy)
{
	P11KitPin *pin;

	pin = calloc (1, sizeof (P11KitPin));
	if (pin == NULL)
		return NULL;

	pin->ref_count = 1;
	pin->buffer = buffer;
	pin->length = length;
	pin->destroy = destroy;

	return pin;
}

/**
 * p11_kit_pin_get_value:
 * @pin: the P11KitPin
 * @length: a location to return the value length
 *
 * Get the PIN value from a P11KitPin. @length will be set to the
 * length of the value.
 *
 * The value returned is owned by the P11KitPin and should not be modified.
 * It remains valid as long as a reference to the PIN is held. The PIN value
 * will not contain an extra null-terminator character.
 *
 * Returns: the value for the PIN.
 */
const unsigned char*
p11_kit_pin_get_value (P11KitPin *pin, size_t *length)
{
	if (length)
		*length = pin->length;
	return pin->buffer;
}

/**
 * p11_kit_pin_get_length
 * @pin: the P11KitPin
 *
 * Get the length of the PIN value from a P11KitPin.
 *
 * Returns: the length of the PIN value.
 */
size_t
p11_kit_pin_get_length (P11KitPin *pin)
{
	return pin->length;
}

/**
 * p11_kit_pin_ref:
 * @pin: the P11KitPin
 *
 * Add a reference to a P11KitPin. This should be matched with a later call
 * to p11_kit_pin_unref(). As long as at least one reference is held, the PIN
 * will remain valid and in memory.
 *
 * Returns: the @pin pointer, for convenience sake.
 */
P11KitPin*
p11_kit_pin_ref (P11KitPin *pin)
{
	_p11_lock ();

		pin->ref_count++;

	_p11_unlock ();

	return pin;
}

/**
 * p11_kit_pin_unref:
 * @pin: the P11KitPin
 *
 * Remove a reference from a P11KitPin. When all references have been removed
 * then the PIN will be freed and will no longer be in memory.
 */
void
p11_kit_pin_unref (P11KitPin *pin)
{
	int last = 0;

	_p11_lock ();

		last = (pin->ref_count == 1);
		pin->ref_count--;

	_p11_unlock ();

	if (last) {
		if (pin->destroy)
			(pin->destroy) (pin->buffer);
		free (pin);
	}
}
