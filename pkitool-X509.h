#ifndef PKITOOL_X509_H
#define PKITOOL_X509_H

#include "pkitool-openssl.h"


static
void x509_set_version(X509 *crt)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* X509_get_version() returns the numerical value of
   * the version field of certificate x. These correspond
   * to the constants X509_VERSION_1, X509_VERSION_2, and X509_VERSION_3.
   * Note: the values of these constants are defined by
   * standards (X.509 et al) to be one less than the certificate version.
   * So X509_VERSION_3 has value 2 and X509_VERSION_1 has value 0.*/
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

  /* X509_get_pubkey() attempts to decode the public key for certificate x.
   * If successful it returns the public key as an EVP_PKEY pointer with
   * its reference count incremented: this means the returned
   * key must be freed up after use.
   * X509_get0_pubkey() is similar except it does not increment
   * the reference count of the returned EVP_PKEY so it must not be freed up after use.*/
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


  /* X509_get0_notBefore() and X509_get0_notAfter() return
   * the notBefore and notAfter fields of certificate x respectively.
   * The value returned is an internal pointer which must not be freed up after the call. */  
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

  /* X509_sign() signs certificate x using private key pkey
   * and message digest md and sets the signature in x.
   * X509_sign_ctx() also signs certificate x but
   * uses the parameters contained in digest context ctx. */
  if (0 == X509_sign(crt, skey, EVP_sha256()))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
      goto err;      
    }

 err:
  BIO_free(out_bio);
  
}




#endif
