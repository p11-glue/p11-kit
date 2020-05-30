#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <libtasn1.h>

const asn1_static_node openssl_asn1_tab[] = {
  { "OPENSSL", 536875024, NULL },
  { NULL, 1073741836, NULL },
  { "CertAux", 1610612741, NULL },
  { "trust", 1610629131, NULL },
  { NULL, 12, NULL },
  { "reject", 1610637323, NULL },
  { NULL, 1073745928, "0"},
  { NULL, 12, NULL },
  { "alias", 1073758242, NULL },
  { "keyid", 1073758215, NULL },
  { "other", 536895499, NULL },
  { NULL, 1073745928, "1"},
  { NULL, 2, "AlgorithmIdentifier"},
  { "AlgorithmIdentifier", 536870917, NULL },
  { "algorithm", 1073741836, NULL },
  { "parameters", 541081613, NULL },
  { "algorithm", 1, NULL },
  { NULL, 0, NULL }
};
