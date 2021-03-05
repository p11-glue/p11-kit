/*
 * Copyright (c) 2018, Red Hat Inc.
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
 * Author: Laszlo Ersek <lersek@redhat.com>
 */

#include "config.h"

#include "buffer.h"  /* p11_buffer */
#include "debug.h"   /* return_val_if_fail() */
#include "message.h" /* p11_message() */
#include "extract.h" /* p11_extract_edk2_cacerts() */

#include <stdint.h>  /* UINT32_MAX */
#include <limits.h>  /* SSIZE_MAX */

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

/* types from the UEFI 2.7 spec, section "31.4.1 Signature Database" */
typedef struct {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
} efi_guid;

typedef struct {
	efi_guid signature_type;
	uint32_t signature_list_size;
	uint32_t signature_header_size;
	uint32_t signature_size;
} efi_signature_list;

typedef struct {
	efi_guid signature_owner;
} efi_signature_data;

/*
 * EFI_CERT_X509_GUID (A5C059A1-94E4-4AA7-87B5-AB155C2BF072) from the UEFI 2.7
 * spec, in host byte order
 */
static const efi_guid efi_cert_x509_guid_host = {
	0xa5c059a1,
	0x94e4,
	0x4aa7,
	{ 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 }
};

/*
 * the GUID identifying this extractor as "agent"
 * (DCDD3B50-F405-43FD-96BE-BD33B1734776, generated with "uuidgen"), in host
 * byte order
 */
static const efi_guid agent_guid_host = {
	0xdcdd3b50,
	0xf405,
	0x43fd,
	{ 0x96, 0xbe, 0xbd, 0x33, 0xb1, 0x73, 0x47, 0x76 }
};

/* serialization helpers */
static void
buffer_add_uint16 (p11_buffer *buffer,
                   uint16_t uint16)
{
	uint8_t uint16_buf[2];

	uint16_buf[0] = uint16;
	uint16_buf[1] = uint16 >> 8;
	p11_buffer_add (buffer, &uint16_buf, sizeof uint16_buf);
}

static void
buffer_add_uint32 (p11_buffer *buffer,
                   uint32_t uint32)
{
	uint8_t uint32_buf[4];

	uint32_buf[0] = uint32;
	uint32_buf[1] = uint32 >> 8;
	uint32_buf[2] = uint32 >> 16;
	uint32_buf[3] = uint32 >> 24;
	p11_buffer_add (buffer, &uint32_buf, sizeof uint32_buf);
}

static void
buffer_add_efi_guid (p11_buffer *buffer,
                     const efi_guid *guid)
{
	buffer_add_uint32 (buffer, guid->data1);
	buffer_add_uint16 (buffer, guid->data2);
	buffer_add_uint16 (buffer, guid->data3);
	p11_buffer_add (buffer, guid->data4, sizeof guid->data4);
}

static void
buffer_add_efi_signature_list (p11_buffer *buffer,
                               const efi_signature_list *siglist)
{
	buffer_add_efi_guid (buffer, &siglist->signature_type);
	buffer_add_uint32 (buffer, siglist->signature_list_size);
	buffer_add_uint32 (buffer, siglist->signature_header_size);
	buffer_add_uint32 (buffer, siglist->signature_size);
}

static void
buffer_add_efi_signature_data (p11_buffer *buffer,
                               const efi_signature_data *sigdata)
{
	buffer_add_efi_guid (buffer, &sigdata->signature_owner);
}

/* main routine */
static bool
prepare_edk2_buffer (p11_enumerate *ex,
                     p11_buffer *buffer)
{
	efi_signature_list siglist;
	efi_signature_data sigdata;
	CK_RV rv;
	size_t size;

	/*
	 * set "siglist.signature_type" and "sigdata.signature_owner" for reuse
	 * across all certificates
	 */
	siglist.signature_type = efi_cert_x509_guid_host;
	sigdata.signature_owner = agent_guid_host;

	/* also reuse a zero "siglist.signature_header_size" */
	siglist.signature_header_size = 0;

	/* for every certificate */
	while ((rv = p11_kit_iter_next (ex->iter)) == CKR_OK) {
		size = sizeof sigdata;

		/*
		 * set the variable size fields in "siglist" while catching any
		 * (unlikely) integer overflows
		 */
		return_val_if_fail (ex->cert_len <= UINT32_MAX - size, false);
		size += ex->cert_len;
		siglist.signature_size = size;

		return_val_if_fail (sizeof siglist <= UINT32_MAX - size, false);
		size += sizeof siglist;
		siglist.signature_list_size = size;

		/* serialize the headers */
		buffer_add_efi_signature_list (buffer, &siglist);
		buffer_add_efi_signature_data (buffer, &sigdata);

		/* serialize the DER encoding of the certificate */
		return_val_if_fail (ex->cert_len <= SSIZE_MAX, false);
		p11_buffer_add (buffer, ex->cert_der, ex->cert_len);
	}

	if (rv != CKR_CANCEL) {
		p11_message (_("failed to find certificate: %s"),
		             p11_kit_strerror (rv));
		return false;
	}

	return_val_if_fail (p11_buffer_ok (buffer), false);
	return true;
}

bool
p11_extract_edk2_cacerts (p11_enumerate *ex,
                          const char *destination)
{
	p11_buffer buffer;
	p11_save_file *file;
	bool ret;

	p11_buffer_init (&buffer, 1024 * 10);
	ret = prepare_edk2_buffer (ex, &buffer);
	if (ret) {
		file = p11_save_open_file (destination, NULL, ex->flags);
		ret = p11_save_write_and_finish (file, buffer.data, buffer.len);
	}

	p11_buffer_uninit (&buffer);
	return ret;
}
