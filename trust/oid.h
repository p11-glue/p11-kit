/*
 * Copyright (C) 2012 Red Hat Inc.
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

#ifndef P11_OIDS_H_
#define P11_OIDS_H_

#include "compat.h"

bool           p11_oid_simple  (const unsigned char *oid,
                                int len);

unsigned int   p11_oid_hash    (const void *oid);

bool           p11_oid_equal   (const void *oid_one,
                                const void *oid_two);

int            p11_oid_length  (const unsigned char *oid);

/*
 * 2.5.4.3: CN or commonName
 */
static const unsigned char P11_OID_CN[] =
	{ 0x06, 0x03, 0x55, 0x04, 0x03, };

/*
 * 2.5.4.10: O or organization
 */
static const unsigned char P11_OID_O[] =
	{ 0x06, 0x03, 0x55, 0x04, 0x0a, };

/*
 * 2.5.4.11: OU or organizationalUnit
 */
static const unsigned char P11_OID_OU[] =
	{ 0x06, 0x03, 0x55, 0x04, 0x0b, };

/*
 * Our support of certificate extensions and so on is not limited to what is
 * listed here. This is simply the OIDs used by the parsing code that generates
 * backwards compatible PKCS#11 objects for NSS and the like.
 */

/*
 * 2.5.29.14: SubjectKeyIdentifier
 */
static const unsigned char P11_OID_SUBJECT_KEY_IDENTIFIER[] =
	{ 0x06, 0x03, 0x55, 0x1d, 0x0e };
static const char P11_OID_SUBJECT_KEY_IDENTIFIER_STR[] = "2.5.29.14";

/*
 * 2.5.29.15: KeyUsage
 *
 * Defined in RFC 5280
 */
static const unsigned char P11_OID_KEY_USAGE[] =
	{ 0x06, 0x03, 0x55, 0x1d, 0x0f };
static const char P11_OID_KEY_USAGE_STR[] = { "2.5.29.15" };

enum {
	P11_KU_DIGITAL_SIGNATURE = 128,
	P11_KU_NON_REPUDIATION = 64,
	P11_KU_KEY_ENCIPHERMENT = 32,
	P11_KU_DATA_ENCIPHERMENT = 16,
	P11_KU_KEY_AGREEMENT = 8,
	P11_KU_KEY_CERT_SIGN = 4,
	P11_KU_CRL_SIGN = 2,
	P11_KU_ENCIPHER_ONLY = 1,
	P11_KU_DECIPHER_ONLY = 32768,
};

/*
 * 2.5.29.19: BasicConstraints
 *
 * Defined in RFC 5280
 */
static const unsigned char P11_OID_BASIC_CONSTRAINTS[] =
	{ 0x06, 0x03, 0x55, 0x1d, 0x13 };
static const char P11_OID_BASIC_CONSTRAINTS_STR[] = "2.5.29.19";

/*
 * 2.5.29.37: ExtendedKeyUsage
 *
 * Defined in RFC 5280
 */
static const unsigned char P11_OID_EXTENDED_KEY_USAGE[] =
	{ 0x06, 0x03, 0x55, 0x1d, 0x25 };
static const char P11_OID_EXTENDED_KEY_USAGE_STR[] = "2.5.29.37";

/*
 * 1.3.6.1.4.1.3319.6.10.1: OpenSSL reject extension
 *
 * An internally defined certificate extension.
 *
 * OpenSSL contains a list of OID extended key usages to reject.
 * The normal X.509 model is to only *include* the extended key
 * usages that are to be allowed (ie: a whitelist). It's not clear
 * exactly how valid and useful the reject per extended key usage
 * model is.
 *
 * However in order to parse openssl trust policy information and
 * be able to write it back out in the same way, we define a custom
 * certificate extension to store it.
 *
 * It is not expected (or supported) for others outside of p11-kit
 * to read this information at this point.
 *
 * This extension is never marked critical. It is not necessary to
 * respect information in this certificate extension given that the
 * ExtendedKeyUsage extension carries the same information as a
 * whitelist.
 */
static const unsigned char P11_OID_OPENSSL_REJECT[] =
	{ 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x99, 0x77, 0x06, 0x0a, 0x01 };
static const char P11_OID_OPENSSL_REJECT_STR[] = "1.3.6.1.4.1.3319.6.10.1";

/*
 * 1.3.6.1.5.5.7.3.1: Server Auth
 *
 * Defined in RFC 5280
 */
static const unsigned char P11_OID_SERVER_AUTH[] =
	{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
static const char P11_OID_SERVER_AUTH_STR[] = "1.3.6.1.5.5.7.3.1";

/*
 * 1.3.6.1.5.5.7.3.2: Client Auth
 *
 * Defined in RFC 5280
 */
static const unsigned char P11_OID_CLIENT_AUTH[] =
	{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };
static const char P11_OID_CLIENT_AUTH_STR[] = "1.3.6.1.5.5.7.3.2";

/*
 * 1.3.6.1.5.5.7.3.3: Code Signing
 *
 * Defined in RFC 5280
 */
static const unsigned char P11_OID_CODE_SIGNING[] =
	{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 };
static const char P11_OID_CODE_SIGNING_STR[] = "1.3.6.1.5.5.7.3.3";

/*
 * 1.3.6.1.5.5.7.3.4: Email Protection
 *
 * Defined in RFC 5280
 */
static const unsigned char P11_OID_EMAIL_PROTECTION[] =
	{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04 };
static const char P11_OID_EMAIL_PROTECTION_STR[] = "1.3.6.1.5.5.7.3.4";

/*
 * 1.3.6.1.5.5.7.3.5: IPSec End System
 *
 * Defined in RFC 2459
 */
static const unsigned char P11_OID_IPSEC_END_SYSTEM[] =
	{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x05 };
static const char P11_OID_IPSEC_END_SYSTEM_STR[] = "1.3.6.1.5.5.7.3.5";

/*
 * 1.3.6.1.5.5.7.3.6: IPSec Tunnel
 *
 * Defined in RFC 2459
 */
static const unsigned char P11_OID_IPSEC_TUNNEL[] =
	{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x06 };
static const char P11_OID_IPSEC_TUNNEL_STR[] = "1.3.6.1.5.5.7.3.6";

/*
 * 1.3.6.1.5.5.7.3.7: IPSec User
 *
 * Defined in RFC 2459
 */
static const unsigned char P11_OID_IPSEC_USER[] =
	{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x07 };
static const char P11_OID_IPSEC_USER_STR[] = "1.3.6.1.5.5.7.3.7";

/*
 * 1.3.6.1.5.5.7.3.8: Time Stamping
 *
 * Defined in RFC 2459
 */
static const unsigned char P11_OID_TIME_STAMPING[] =
	{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08 };
static const char P11_OID_TIME_STAMPING_STR[] = "1.3.6.1.5.5.7.3.8";
/*
 * 1.3.6.1.4.1.3319.6.10.16: Reserved key purpose
 *
 * An internally defined reserved/dummy key purpose
 *
 * This is used with ExtendedKeyUsage certificate extensions to
 * be a place holder when no other purposes are defined.
 *
 * In theory such a certificate should be blacklisted. But in reality
 * many implementations use such empty sets of purposes. RFC 5280 requires
 * at least one purpose in an ExtendedKeyUsage.
 *
 * Obviously this purpose should never be checked against.
 */
static const unsigned char P11_OID_RESERVED_PURPOSE[] =
	{ 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x99, 0x77, 0x06, 0x0a, 0x10 };
static const char P11_OID_RESERVED_PURPOSE_STR[] = "1.3.6.1.4.1.3319.6.10.16";

#endif
