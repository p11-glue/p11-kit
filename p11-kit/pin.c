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

#define P11_DEBUG_FLAG P11_DEBUG_PIN
#include "debug.h"
#include "dict.h"
#include "library.h"
#include "message.h"
#include "pkcs11.h"
#include "p11-kit.h"
#include "pin.h"
#include "private.h"
#include "array.h"

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
 * password associated with a given pin source.
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
 * This callback will be called if no other callback is registered for a 'pin-source'.
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
	p11_dict *pin_sources;
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

static bool
register_callback_unlocked (const char *pin_source,
                            PinCallback *cb)
{
	p11_array *callbacks = NULL;
	char *name;

	name = strdup (pin_source);
	return_val_if_fail (name != NULL, false);

	if (gl.pin_sources == NULL) {
		gl.pin_sources = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal,
		                               free, (p11_destroyer)p11_array_free);
		return_val_if_fail (gl.pin_sources != NULL, false);
	}

	if (gl.pin_sources != NULL)
		callbacks = p11_dict_get (gl.pin_sources, name);

	if (callbacks == NULL) {
		callbacks = p11_array_new (unref_pin_callback);
		return_val_if_fail (callbacks != NULL, false);
		if (!p11_dict_set (gl.pin_sources, name, callbacks))
			return_val_if_reached (false);
		name = NULL;
	}

	if (!p11_array_push (callbacks, cb))
		return_val_if_reached (false);

	free (name);
	return true;
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
 * Returns: Returns negative if registering fails.
 */
int
p11_kit_pin_register_callback (const char *pin_source,
                               p11_kit_pin_callback callback,
                               void *callback_data,
                               p11_kit_pin_destroy_func callback_destroy)
{
	PinCallback *cb;
	bool ret;

	return_val_if_fail (pin_source != NULL, -1);
	return_val_if_fail (callback != NULL, -1);

	cb = calloc (1, sizeof (PinCallback));
	return_val_if_fail (cb != NULL, -1);

	cb->refs = 1;
	cb->func = callback;
	cb->user_data = callback_data;
	cb->destroy = callback_destroy;

	p11_lock ();

	ret = register_callback_unlocked (pin_source, cb);

	p11_unlock ();

	return ret ? 0 : -1;
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
p11_kit_pin_unregister_callback (const char *pin_source,
                                 p11_kit_pin_callback callback,
                                 void *callback_data)
{
	PinCallback *cb;
	p11_array *callbacks;
	unsigned int i;

	return_if_fail (pin_source != NULL);
	return_if_fail (callback != NULL);

	p11_lock ();

		if (gl.pin_sources) {
			callbacks = p11_dict_get (gl.pin_sources, pin_source);
			if (callbacks) {
				for (i = 0; i < callbacks->num; i++) {
					cb = callbacks->elem[i];
					if (cb->func == callback && cb->user_data == callback_data) {
						p11_array_remove (callbacks, i);
						break;
					}
				}

				if (callbacks->num == 0)
					p11_dict_remove (gl.pin_sources, pin_source);
			}

			/* When there are no more pin sources, get rid of the hash table */
			if (p11_dict_size (gl.pin_sources) == 0) {
				p11_dict_free (gl.pin_sources);
				gl.pin_sources = NULL;
			}
		}

	p11_unlock ();
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
P11KitPin *
p11_kit_pin_request (const char *pin_source,
                     P11KitUri *pin_uri,
                     const char *pin_description,
                     P11KitPinFlags pin_flags)
{
	PinCallback **snapshot = NULL;
	unsigned int snapshot_count = 0;
	p11_array *callbacks;
	P11KitPin *pin;
	unsigned int i;

	return_val_if_fail (pin_source != NULL, NULL);

	p11_lock ();

		/* Find and ref the pin source data */
		if (gl.pin_sources) {
			callbacks = p11_dict_get (gl.pin_sources, pin_source);

			/* If we didn't find any snapshots try the global ones */
			if (callbacks == NULL)
				callbacks = p11_dict_get (gl.pin_sources, P11_KIT_PIN_FALLBACK);

			if (callbacks != NULL && callbacks->num) {
				snapshot = memdup (callbacks->elem, sizeof (void *) * callbacks->num);
				snapshot_count = callbacks->num;
				for (i = 0; snapshot && i < snapshot_count; i++)
					ref_pin_callback (snapshot[i]);
			}
		}

	p11_unlock ();

	if (snapshot == NULL)
		return NULL;

	for (pin = NULL, i = snapshot_count; pin == NULL && i > 0; i--) {
		pin = (snapshot[i - 1]->func) (pin_source, pin_uri, pin_description, pin_flags,
		                               snapshot[i - 1]->user_data);
	}

	p11_lock ();
		for (i = 0; i < snapshot_count; i++)
			unref_pin_callback (snapshot[i]);
		free (snapshot);
	p11_unlock ();

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
 * If @pin_flags contains the %P11_KIT_PIN_FLAGS_RETRY flag, then this
 * callback will always return %NULL. This is to prevent endless loops
 * where an application is expecting to interact with a prompter, but
 * instead is interacting with this callback reading a file over and over.
 *
 * This callback fails on files larger than 4 Kilobytes.
 *
 * This callback is not registered by default. It may have security
 * implications depending on the source of the PKCS\#11 URI and the PKCS\#11
 * in use. To register it, use code like the following:
 *
 * <informalexample><programlisting>
 * p11_kit_pin_register_callback (P11_KIT_PIN_FALLBACK, p11_kit_pin_file_callback,
 *                                NULL, NULL);
 * </programlisting></informalexample>
 *
 * Returns: a referenced PIN with the file contents, or %NULL if the file
 *          could not be read
 */
P11KitPin *
p11_kit_pin_file_callback (const char *pin_source,
                           P11KitUri *pin_uri,
                           const char *pin_description,
                           P11KitPinFlags pin_flags,
                           void *callback_data)
{
	const size_t block = 1024;
	unsigned char *buffer;
	unsigned char *memory;
	size_t used, allocated;
	int error = 0;
	int fd;
	int res;

	return_val_if_fail (pin_source != NULL, NULL);

	/* We don't support retries */
	if (pin_flags & P11_KIT_PIN_FLAGS_RETRY)
		return NULL;

	fd = open (pin_source, O_BINARY | O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return NULL;

	buffer = NULL;
	used = 0;
	allocated = 0;

	for (;;) {
		if (used + block > 4096) {
			error = EFBIG;
			break;
		}
		if (used + block > allocated) {
			memory = realloc (buffer, used + block);
			if (memory == NULL) {
				error = ENOMEM;
				break;
			}
			buffer = memory;
			allocated = used + block;
		}

		res = read (fd, buffer + used, allocated - used);
		if (res < 0) {
			if (errno == EAGAIN)
				continue;
			error = errno;
			break;
		} else if (res == 0) {
			break;
		} else {
			used += res;
		}
	}

	close (fd);

	if (error != 0) {
		free (buffer);
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
 * Create a new P11KitPin with the given PIN value. This function is
 * usually used from within registered PIN callbacks.
 *
 * Exactly @length bytes from @value are used. Null terminated strings,
 * or encodings are not considered. A copy of the @value will be made.
 *
 * Returns: The newly allocated P11KitPin, which should be freed with
 *          p11_kit_pin_unref() when no longer needed.
 */
P11KitPin *
p11_kit_pin_new (const unsigned char *value, size_t length)
{
	unsigned char *copy;
	P11KitPin *pin;

	copy = malloc (length);
	return_val_if_fail (copy != NULL, NULL);

	memcpy (copy, value, length);
	pin = p11_kit_pin_new_for_buffer (copy, length, free);
	return_val_if_fail (pin != NULL, NULL);

	return pin;
}

/**
 * p11_kit_pin_new_for_string:
 * @value: the value of the PIN
 *
 * Create a new P11KitPin for the given null-terminated string, such as a
 * password. This function is usually used from within registered
 * PIN callbacks.
 *
 * The PIN will consist of the string not including the null terminator.
 * String encoding is not considered. A copy of the @value will be made.
 *
 * Returns: The newly allocated P11KitPin, which should be freed with
 *     p11_kit_pin_unref() when no longer needed.
 */
P11KitPin *
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
 * Create a new P11KitPin which will use @buffer for the PIN value.
 * This function is usually used from within registered PIN callbacks.
 *
 * The buffer will not be copied. String encodings and null characters
 * are not considered.
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
 *          p11_kit_pin_unref() when no longer needed.
 */
P11KitPin *
p11_kit_pin_new_for_buffer (unsigned char *buffer, size_t length,
                            p11_kit_pin_destroy_func destroy)
{
	P11KitPin *pin;

	pin = calloc (1, sizeof (P11KitPin));
	return_val_if_fail (pin != NULL, NULL);

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
const unsigned char *
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
P11KitPin *
p11_kit_pin_ref (P11KitPin *pin)
{
	p11_lock ();

		pin->ref_count++;

	p11_unlock ();

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
	bool last = false;

	p11_lock ();

		last = (pin->ref_count == 1);
		pin->ref_count--;

	p11_unlock ();

	if (last) {
		if (pin->destroy)
			(pin->destroy) (pin->buffer);
		free (pin);
	}
}
