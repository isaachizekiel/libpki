#ifndef PKITOOL_X509_REQUEST
#define PKITOOL_X509_REQUEST

#include "pkitool-openssl.h"


// int X509_REQ_set_version(X509_REQ *x, long version);
static void
x509_req_set_version(X509_REQ *req, long version)
{
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  if ( 1 != X509_REQ_set_version(req, version))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
    }
    

  BIO_free(out_bio);
  
  
}

// X509_NAME *X509_REQ_get_subject_name(const X509_REQ *req);
static void
x509_req_get_subject_name(X509_REQ *req, X509_NAME **name)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  if ( ! (*name = X509_REQ_get_subject_name(req)))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
    }

  BIO_free(out_bio);
  
}
  

// int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);
static void
x509_req_set_pk(X509_REQ *req, EVP_PKEY *pk)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  if ( 1 != X509_REQ_set_pubkey(req, pk))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);      
    }

  BIO_free(out_bio);
  
}

// int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md);
static void
x509_req_sign(X509_REQ *req, EVP_PKEY *sk)
{
  
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* All functions return the size of the signature
   * in bytes for success and zero for failure. */
  if ( 0 == X509_REQ_sign(req, sk, EVP_sha256()))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);            
    }

  BIO_free(out_bio);
  
}


#endif
