#ifndef PKITOOL_RSA_H
#define PKITOOL_RSA_H

#include "pkitool-openssl.h"


BN_GENCB *
RSA_generate_keypair_progress_cb()
{
  
  return NULL;
  
}

/* int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb); */
static void
rsa_generate_keypair(RSA **rsa)
{
  
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);;
  BIGNUM *e = BN_new();

  BN_set_word(e, RSA_F4);
  
  if (1 != RSA_generate_key_ex(*rsa, 1024, e, NULL))
    {
      BIO_printf(out_bio, "\nError generating RSA key\n");
      goto err;
    }
  
 err:
  BIO_free(out_bio);
  BN_free(e);
  
}

static void
rsa_check_key(RSA *rsa)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);;
  /* Check if our rsa is valid */
  if ( ! RSA_check_key(rsa))
    {
      BIO_printf(out_bio, "\nError Validating RSA Key\n");
      goto err;
    }

 err:
  BIO_free(out_bio);
  
}


#endif
