#!/bin/sh

set -e

testdir=$PWD/test-messages-$$
test -d "$testdir" || mkdir "$testdir"

cleanup () {
	rm -rf "$testdir"
}
trap cleanup 0

cd "$testdir"

cat > messages.exp <<EOF
CKR_CANCEL: The operation was cancelled
CKR_FUNCTION_CANCELED: The operation was cancelled
CKR_HOST_MEMORY: Insufficient memory available
CKR_SLOT_ID_INVALID: The specified slot ID is not valid
CKR_GENERAL_ERROR: Internal error
CKR_FUNCTION_FAILED: The operation failed
CKR_ARGUMENTS_BAD: Invalid arguments
CKR_NEED_TO_CREATE_THREADS: The module cannot create needed threads
CKR_CANT_LOCK: The module cannot lock data properly
CKR_ATTRIBUTE_READ_ONLY: The field is read-only
CKR_ATTRIBUTE_SENSITIVE: The field is sensitive and cannot be revealed
CKR_ATTRIBUTE_TYPE_INVALID: The field is invalid or does not exist
CKR_ATTRIBUTE_VALUE_INVALID: Invalid value for field
CKR_DATA_INVALID: The data is not valid or unrecognized
CKR_DATA_LEN_RANGE: The data is too long
CKR_DEVICE_ERROR: An error occurred on the device
CKR_DEVICE_MEMORY: Insufficient memory available on the device
CKR_DEVICE_REMOVED: The device was removed or unplugged
CKR_ENCRYPTED_DATA_INVALID: The encrypted data is not valid or unrecognized
CKR_ENCRYPTED_DATA_LEN_RANGE: The encrypted data is too long
CKR_FUNCTION_NOT_SUPPORTED: This operation is not supported
CKR_KEY_HANDLE_INVALID: The key is missing or invalid
CKR_KEY_SIZE_RANGE: The key is the wrong size
CKR_KEY_TYPE_INCONSISTENT: The key is of the wrong type
CKR_KEY_NOT_NEEDED: No key is needed
CKR_KEY_CHANGED: The key is different than before
CKR_KEY_NEEDED: A key is needed
CKR_KEY_INDIGESTIBLE: Cannot include the key in the digest
CKR_KEY_FUNCTION_NOT_PERMITTED: This operation cannot be done with this key
CKR_KEY_NOT_WRAPPABLE: The key cannot be wrapped
CKR_KEY_UNEXTRACTABLE: Cannot export this key
CKR_MECHANISM_INVALID: The crypto mechanism is invalid or unrecognized
CKR_MECHANISM_PARAM_INVALID: The crypto mechanism has an invalid argument
CKR_OBJECT_HANDLE_INVALID: The object is missing or invalid
CKR_OPERATION_ACTIVE: Another operation is already taking place
CKR_OPERATION_NOT_INITIALIZED: No operation is taking place
CKR_PIN_INCORRECT: The password or PIN is incorrect
CKR_PIN_INVALID: The password or PIN is invalid
CKR_PIN_LEN_RANGE: The password or PIN is of an invalid length
CKR_PIN_EXPIRED: The password or PIN has expired
CKR_PIN_LOCKED: The password or PIN is locked
CKR_SESSION_CLOSED: The session is closed
CKR_SESSION_COUNT: Too many sessions are active
CKR_SESSION_HANDLE_INVALID: The session is invalid
CKR_SESSION_READ_ONLY: The session is read-only
CKR_SESSION_EXISTS: An open session exists
CKR_SESSION_READ_ONLY_EXISTS: A read-only session exists
CKR_SESSION_READ_WRITE_SO_EXISTS: An administrator session exists
CKR_SIGNATURE_INVALID: The signature is bad or corrupted
CKR_SIGNATURE_LEN_RANGE: The signature is unrecognized or corrupted
CKR_TEMPLATE_INCOMPLETE: Certain required fields are missing
CKR_TEMPLATE_INCONSISTENT: Certain fields have invalid values
CKR_TOKEN_NOT_PRESENT: The device is not present or unplugged
CKR_TOKEN_NOT_RECOGNIZED: The device is invalid or unrecognizable
CKR_TOKEN_WRITE_PROTECTED: The device is write protected
CKR_UNWRAPPING_KEY_HANDLE_INVALID: Cannot import because the key is invalid
CKR_UNWRAPPING_KEY_SIZE_RANGE: Cannot import because the key is of the wrong size
CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: Cannot import because the key is of the wrong type
CKR_USER_ALREADY_LOGGED_IN: You are already logged in
CKR_USER_NOT_LOGGED_IN: No user has logged in
CKR_USER_PIN_NOT_INITIALIZED: The user's password or PIN is not set
CKR_USER_TYPE_INVALID: The user is of an invalid type
CKR_USER_ANOTHER_ALREADY_LOGGED_IN: Another user is already logged in
CKR_USER_TOO_MANY_TYPES: Too many users of different types are logged in
CKR_WRAPPED_KEY_INVALID: Cannot import an invalid key
CKR_WRAPPED_KEY_LEN_RANGE: Cannot import a key of the wrong size
CKR_WRAPPING_KEY_HANDLE_INVALID: Cannot export because the key is invalid
CKR_WRAPPING_KEY_SIZE_RANGE: Cannot export because the key is of the wrong size
CKR_WRAPPING_KEY_TYPE_INCONSISTENT: Cannot export because the key is of the wrong type
CKR_RANDOM_SEED_NOT_SUPPORTED: Unable to initialize the random number generator
CKR_RANDOM_NO_RNG: No random number generator available
CKR_DOMAIN_PARAMS_INVALID: The crypto mechanism has an invalid parameter
CKR_BUFFER_TOO_SMALL: Not enough space to store the result
CKR_SAVED_STATE_INVALID: The saved state is invalid
CKR_INFORMATION_SENSITIVE: The information is sensitive and cannot be revealed
CKR_STATE_UNSAVEABLE: The state cannot be saved
CKR_CRYPTOKI_NOT_INITIALIZED: The module has not been initialized
CKR_CRYPTOKI_ALREADY_INITIALIZED: The module has already been initialized
CKR_MUTEX_BAD: Cannot lock data
CKR_MUTEX_NOT_LOCKED: The data cannot be locked
CKR_FUNCTION_REJECTED: The request was rejected by the user
EOF

${WINE} "$abs_top_builddir"/p11-kit/print-messages | tr -d '\r' > messages.out

echo 1..1

: ${DIFF=diff}
if ${DIFF} messages.exp messages.out > messages.diff; then
	echo "ok 1 /messages/return-code"
else
	echo "not ok 1 /messages/return-code"
	sed 's/^/# /' messages.diff
	exit 1
fi
