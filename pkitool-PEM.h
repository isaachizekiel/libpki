#ifndef PKITOOL_PEM_H
#define PKITOOL_PEM_H

#include "pkitool-openssl.h"

/*
 * EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x,
 * pem_password_cb *cb, void *u); */

static void 
pem_read_evp_sk(char *path, EVP_PKEY **key)
{
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO *key_bio = BIO_new(BIO_s_file());
  
  BIO_read_filename(key_bio, path);

  /* The PEM functions read or write structures in PEM format.
   * In this sense PEM format is simply base64 encoded data surrounded by header lines. */
  if (!PEM_read_bio_PrivateKey(key_bio, &*key, NULL, NULL))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
      goto err;
    }

 err:
  BIO_free(out_bio);
  BIO_free(key_bio);
}

/* EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x,
 * pem_password_cb *cb, void *u); */
static void 
pem_read_evp_pk(char *path, EVP_PKEY **key)
{
  
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO *key_bio = BIO_new(BIO_s_file());

  /* BIO_s_file() returns the BIO file method.
   * As its name implies it is a wrapper round the stdio
   * FILE structure and it is a source/sink BIO. */
  BIO_read_filename(key_bio, path);

  if (!PEM_read_bio_PUBKEY(key_bio, &*key, NULL, NULL))
    {
      BIO_printf(out_bio, "\n%s %d %s\n", __FILE__, __LINE__, __func__);      
      ERR_print_errors(out_bio);
      goto err;      
    }
  
 err:
  BIO_free(out_bio);
  BIO_free(key_bio);
  
}

static
void pem_x509_read(char *path, X509 **crt)
{
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO *crt_bio = BIO_new(BIO_s_file());
  
  BIO_read_filename(crt_bio, path);
  if ( ! (*crt = PEM_read_bio_X509(crt_bio, NULL, 0, NULL) ))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);      
    }

  BIO_free(out_bio);
  BIO_free(crt_bio);
  
}


/*
 * int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x,
 * const EVP_CIPHER *enc, unsigned char *kstr, int klen,
 * pem_password_cb *cb, void *u); */

static void 
pem_write_evp_sk(char *path, EVP_PKEY *key)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO *key_bio = BIO_new(BIO_s_file());
  
  BIO_write_filename(key_bio, path);

  if (1 != PEM_write_bio_PrivateKey(key_bio, key, NULL, NULL, 0, NULL, NULL))
    {
      BIO_printf(out_bio, "\n%s %d %s\n", __FILE__, __LINE__, __func__);      
      ERR_print_errors(out_bio);
      goto err;
    }
  
 err:
  BIO_free(out_bio);
  BIO_free(key_bio);  

}


/* int PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x); */

static void 
pem_write_evp_pk(char *path, EVP_PKEY *key)
{
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO *key_bio = BIO_new(BIO_s_file());
  
  BIO_write_filename(key_bio, path);

  if (1 != PEM_write_bio_PUBKEY(key_bio, key))
    {
      BIO_printf(out_bio, "\n%s %d %s\n", __FILE__, __LINE__, __func__);      
      ERR_print_errors(out_bio);
      goto err;      
    }
  
 err:
  BIO_free(out_bio);
  BIO_free(key_bio);  

}



static void
pem_x509_write(X509 *crt, char *path)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO *crt_bio = BIO_new(BIO_s_file());
  
  BIO_write_filename(crt_bio, path);
    
  if (! PEM_write_bio_X509(crt_bio, crt))
    {    
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
    }

  BIO_free(crt_bio);
  BIO_free(out_bio);
  
}



static void
pem_x509_req_write(X509_REQ *req, char *path)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO *req_bio = BIO_new(BIO_s_file());
  
  BIO_write_filename(req_bio, path);

  if (! PEM_write_bio_X509_REQ(req_bio, req))
    {    
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
    }

  BIO_free(req_bio);
  BIO_free(out_bio);
  
}


#endif
