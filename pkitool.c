#include "pkitool-key-rsa.h"
#include "pkitool-pem.h"

#include "pkitool-cert.h"
#include "pkitool-cert-req.h"

#include "pkitool.h"

/*
 * Keys
 */

void PKIT_RSA_generate_keypair(char *pkpath, char *skpath)
{

  /* Initialize the RSA Object */
  RSA *rsa = RSA_new();
  //EVP_PKEY *key = EVP_PKEY_new();

  /* Generate the rsa key */
  rsa_generate_keypair(&rsa);

  /* Writes the RSA public key to PEM */
  pem_write_rsa_pk(pkpath, rsa);

  /* Writes the RSA private key to PEM */
  pem_write_rsa_sk(skpath, rsa);

  /* Free the RSA Object */
  RSA_free(rsa);
  
}

void
PKIT_PEM_print_RSA_pk(char *pkpath)
{

  /* Initialize the RSA Object */
  RSA *rsa = RSA_new();
    
  pem_read_rsa_pk(pkpath, &rsa);

  rsa_check_key(rsa);

  pem_print_rsa_pk(rsa);
  
  RSA_free(rsa);
  
}

void
PKIT_PEM_print_RSA_sk(char *skpath)
{

  RSA *rsa = RSA_new();
  
  pem_read_rsa_sk(skpath, &rsa);

  rsa_check_key(rsa);

  pem_print_rsa_sk(rsa);
  
  RSA_free(rsa);

  /* FIXME this causes a segfault */
  //RSA_free(rsa);
    
}
