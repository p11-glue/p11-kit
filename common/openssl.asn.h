#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <libtasn1.h>

const ASN1_ARRAY_TYPE openssl_asn1_tab[] = {
  { "OPENSSL", 536875024, NULL },
  { NULL, 1073741836, NULL },
  { "CertAux", 1610612741, NULL },
  { "trust", 1610629131, NULL },
  { NULL, 12, NULL },
  { "reject", 1610637323, NULL },
  { NULL, 1073745928, "0"},
  { NULL, 12, NULL },
  { "alias", 1073758210, "UTF8String"},
  { "keyid", 1073758215, NULL },
  { "other", 536895499, NULL },
  { NULL, 1073745928, "1"},
  { NULL, 2, "AlgorithmIdentifier"},
  { "AlgorithmIdentifier", 1610612741, NULL },
  { "algorithm", 1073741836, NULL },
  { "parameters", 541081613, NULL },
  { "algorithm", 1, NULL },
  { "UTF8String", 536879111, NULL },
  { NULL, 4360, "12"},
  { NULL, 0, NULL }
};
