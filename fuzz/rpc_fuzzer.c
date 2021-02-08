/*
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include "config.h"
#include "test.h"

#include "fuzz/fuzz.h"
#include "library.h"
#include "mock.h"
#include "p11-kit/rpc.h"

#include <assert.h>

static p11_virtual base;

#ifdef __cplusplus
extern "C"
#endif
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    p11_buffer buffer;

    mock_module_init ();
    p11_library_init ();

    p11_buffer_init (&buffer, 0);

    p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);
    base.funcs.C_Initialize (&base.funcs, NULL);

    p11_buffer_add (&buffer, data, size);
    assert (!p11_buffer_failed (&buffer));

    p11_rpc_server_handle (&base.funcs, &buffer, &buffer);

    p11_buffer_uninit (&buffer);
    mock_module_reset ();
    p11_library_uninit ();

    return 0;
}
