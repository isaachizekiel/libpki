#include "pkitool-key-rsa.h"
#include "pkitool-evp-pkey.h"
#include "pkitool-pem.h"

#include "pkitool-cert.h"
#include "pkitool-cert-req.h"

#include "pkitool.h"

/*
 * Keys
 */

void
PKIT_RSA_generate_keypair(char *path)
{

  RSA *rsa = RSA_new();
  EVP_PKEY *key = EVP_PKEY_new();

  /* Begin by generating the key pair */
  rsa_generate_keypair(&rsa);

  /* check weather our rsa keypair is valid */
  rsa_check_key(rsa);


  /* assigns RSA object to EVP_PKEY object */
  evp_pkey_assign_rsa(&key, rsa);

  /* This function can make output the
   * PEM encoded object to any given file discreptor
   * the stdout or file or  ... */
  pem_write_evp_pk(path, key);

  /* see the above comment */
  pem_write_evp_sk(path, key);


  /* When key is freed rsa is also freed
   * because the EVP_PKEY_assign_RSA is executed
   * both objects become one and when one is free
   * both will become free*/
  EVP_PKEY_free(key);
    
}
