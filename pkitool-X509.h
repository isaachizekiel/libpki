#ifndef PKITOOL_X509_H
#define PKITOOL_X509_H

#include "pkitool-openssl.h"


static
void x509_set_version(X509 *crt)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  if (1 != X509_set_version(crt, 2))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
      goto err;
    }


 err:
  BIO_free(out_bio);
  
}

static
void x509_set_pubkey(X509 *crt, EVP_PKEY *pkey)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  if (1 != X509_set_pubkey(crt, pkey))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
      goto err;
    }

 err:
  BIO_free(out_bio);
  
}

static
void x509_set_valid_date(X509 *crt, long valid_secs)
{
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  
  if (! (X509_gmtime_adj(X509_get_notBefore(crt),0)))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
      goto err;      
    }

  
  if(! (X509_gmtime_adj(X509_get_notAfter(crt), valid_secs)))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
      goto err;      
    }

 err:
  BIO_free(out_bio);
    
}


static
void x509_set_sign(X509 *crt, EVP_PKEY *skey)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  
  if (! X509_sign(crt, skey, EVP_sha256()))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
      goto err;      
    }

 err:
  BIO_free(out_bio);
  
}


#endif
