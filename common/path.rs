//
// Copyright (c) 2021 Red Hat Inc.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//     * Redistributions of source code must retain the above
//       copyright notice, this list of conditions and the
//       following disclaimer.
//     * Redistributions in binary form must reproduce the
//       above copyright notice, this list of conditions and
//       the following disclaimer in the documentation and/or
//       other materials provided with the distribution.
//     * The names of contributors to this software may not be
//       used to endorse or promote products derived from this
//       software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
// OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
// AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.
//

use std::ffi::{CStr, CString, OsStr};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::os::unix::ffi::OsStrExt;

#[no_mangle]
pub extern fn p11_path_base(name: *const c_char) -> *mut c_char {
    let slice = unsafe { CStr::from_ptr(name) };
    let path = PathBuf::from(OsStr::from_bytes(slice.to_bytes()));
    let bytes = path
        .file_name()
        .and_then(|base| Some(base.as_bytes()))
        .unwrap_or("".as_bytes());
    CString::new(bytes)
        .and_then(|c_string| Ok(c_string.into_raw()))
        .unwrap_or(std::ptr::null_mut())
}
