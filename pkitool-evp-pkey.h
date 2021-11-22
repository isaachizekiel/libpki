#ifndef PKITOOL_EVP_PKEY_H
#define PKITOOL_EVP_PKEY_H

#include "pkitool-openssl.h"



/* The key pair Generation function */

static void 
evp_pkey_rsa_keygen(EVP_PKEY **pkey)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

  if (!ctx)
    {
      BIO_printf(out_bio, "\nError Initializing EVP_PKEY context\n");
      goto err;
      
    }
  
  if ( 1 != EVP_PKEY_keygen_init(ctx))
    {
      BIO_printf(out_bio, "\nError Initializing EVP_PKEY keygen\n");
      goto err;
    }
  
  if ( 1 != EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048))
    {
      BIO_printf(out_bio, "\nError Setting  EVP_PKEY keygen bits\n");
      goto err;      
    }
 
  /* Generate key */
  if ( 1 != EVP_PKEY_keygen(ctx, &*pkey))
    {     
      BIO_printf(out_bio, "\nError EVP_PKEY keygen\n");
      goto err;
    }

 err:
  BIO_free(out_bio);
  
 
}




#endif
