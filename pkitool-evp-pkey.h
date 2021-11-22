#ifndef PKITOOL_EVP_PKEY_H
#define PKITOOL_EVP_PKEY_H

#include "pkitool-openssl.h"


//int EVP_PKEY_is_a(const EVP_PKEY *pkey, const char *name);
static void
evp_pkey_is_a(EVP_PKEY *key, char *s)
{

}


/* Application data is a BIO to output status to */

/*
EVP_PKEY_CTX_set_app_data(ctx, status_bio);

static int genpkey_cb(EVP_PKEY_CTX *ctx)
{
  char c = '*';
  BIO *b = EVP_PKEY_CTX_get_app_data(ctx);
  int p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);

  if (p == 0)
    c = '.';
  if (p == 1)
    c = '+';
  if (p == 2)
    c = '*';
  if (p == 3)
    c = '\n';
  BIO_write(b, &c, 1);
  (void)BIO_flush(b);
  return 1;
}
*/

//EVP_PKEY_CTX_set_rsa_keygen_bits

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


/* int EVP_PKEY_assign_RSA(EVP_PKEY *pkey, RSA *key); */

static void
evp_pkey_assign_rsa(EVP_PKEY **key, RSA *rsa)
{
  BIO* out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  if ( 1 != EVP_PKEY_assign_RSA(*key, rsa))
    {
      BIO_printf(out_bio, "\nError Assigning RSA to EVP_PKEY \n");
    }
  
}

//  int EVP_PKEY_public_check(EVP_PKEY_CTX *ctx);
static void
evp_pkey_public_check(EVP_PKEY_CTX *ctx)
{
  
}


// int EVP_PKEY_private_check(EVP_PKEY_CTX *ctx);
void
evp_pkey_private_check(EVP_PKEY_CTX *ctx)
{
  
}

//EVP_PKEY_assign_RSA

#endif
