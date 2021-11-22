#ifndef PKITOOL_EVP_PKEY_H
#define PKITOOL_EVP_PKEY_H

#include "pkitool-openssl.h"



// int EVP_PKEY_assign_RSA(EVP_PKEY *pkey, RSA *key);
static void
evp_pkey_assign_rsa(EVP_PKEY **key, RSA *rsa)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  
  if (1 != EVP_PKEY_assign_RSA(*key, rsa))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
      goto err;
    }

 err:
  BIO_free(out_bio);
}


#endif
