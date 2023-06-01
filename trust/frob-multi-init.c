/*
 * gcc -Wall -o frob-multi-init $(pkg-config p11-kit-1 --cflags --libs) -ldl frob-multi-init.c
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>

#include <p11-kit/p11-kit.h>

#define TRUST_SO P11_MODULE_PATH "/p11-kit-trust" SHLEXT

int
main (void)
{
	CK_C_INITIALIZE_ARGS args =
		{ NULL, NULL, NULL, NULL, CKF_OS_LOCKING_OK, NULL, };
	CK_C_GetFunctionList C_GetFunctionList;
	CK_SESSION_HANDLE session;
	CK_FUNCTION_LIST *module;
	CK_SLOT_ID slots[8];
	CK_SESSION_INFO info;
	CK_ULONG count;
	CK_RV rv;
	void *dl;

	dl = dlopen (TRUST_SO, RTLD_LOCAL | RTLD_NOW);
	if (dl == NULL)
		fprintf (stderr, "%s\n", dlerror());
	assert (dl != NULL);

	C_GetFunctionList = dlsym (dl, "C_GetFunctionList");
	assert (C_GetFunctionList != NULL);

	rv = C_GetFunctionList (&module);
	assert (rv == CKR_OK);
	assert (module != NULL);

	rv = module->C_Initialize (&args);
	assert (rv == CKR_OK);

	count = 8;
	rv = module->C_GetSlotList (CK_TRUE, slots, &count);
	assert (rv == CKR_OK);
	assert (count > 1);

	rv = module->C_OpenSession (slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);

	rv = module->C_GetSessionInfo (session, &info);
	assert (rv == CKR_OK);

	rv = p11_kit_initialize_registered ();
	assert (rv == CKR_OK);

	rv = module->C_GetSessionInfo (session, &info);
	if (rv == CKR_OK) {
		printf ("no reinitialization bug\n");
		return 0;

	} else if (rv == CKR_SESSION_HANDLE_INVALID) {
		printf ("reinitialization bug present\n");
		return 1;

	} else {
		printf ("another error: %lu\n", rv);
		return 1;
	}
}
