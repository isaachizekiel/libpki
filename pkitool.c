#include "pkitool-evp-pkey.h"
#include "pkitool-pem.h"

#include "pkitool-cert.h"
#include "pkitool-cert-req.h"

#include "pkitool.h"

/*
 * Keys
 */

void
PKIT_EVP_PKEY_generate_RSA_keypair(char *path)
{

  EVP_PKEY *key = EVP_PKEY_new();
  
  //evp_pkey_rsa_keygen(&pkey);

  pem_read_evp_sk(path, &key);

  pem_write_evp_sk(path, key);

  pem_read_evp_pk(path, &key);
  
  //pem_write_evp_pk(path, key);
  
}
