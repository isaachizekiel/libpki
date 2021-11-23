#include "pkitool-RSA.h"
#include "pkitool-EVP-PKEY.h"
#include "pkitool-PEM.h"
#include "pkitool-X509.h"


#include "pkitool.h"

/*
 * Keys
 */

void
PKIT_RSA_generate_keypair(char *pk, char *sk)
{

  /* Init the basic datastructures */
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
  pem_write_evp_pk(pk, key);

  /* see the above comment */
  pem_write_evp_sk(sk, key);

  /* When key is freed rsa is also freed
   * because the EVP_PKEY_assign_RSA is executed
   * both objects will be pointed by the same pointer
   * when one one of them is free both will become free */
  EVP_PKEY_free(key);
    
}

/*
 * Certificates */
void
PKIT_X509_create_certificate(char *pk, char *sk)
{
  
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);  
  X509 *crt = X509_new();
  //X509_NAME *name = "izak";
  
  long valid_secs = 31536000;

  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY *skey = EVP_PKEY_new();
  
  pem_read_evp_pk(pk, &pkey);  
  pem_read_evp_sk(sk, &skey);

  
  x509_set_version(crt);

  x509_set_pubkey(crt, pkey);

  x509_set_valid_date(crt, valid_secs);

  x509_set_sign(crt, skey);
  
  pem_x509_write(crt);

}

