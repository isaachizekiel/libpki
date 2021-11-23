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


/* EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x,
 * pem_password_cb *cb, void *u); */


static void 
pem_read_evp_pk(char *path, EVP_PKEY **key)
{
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO *key_bio = BIO_new(BIO_s_file());
  
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


/*
 * RSA *PEM_read_bio_RSAPublicKey(BIO *bp,
 * RSA **x, pem_password_cb *cb, void *u); */

static void
pem_read_rsa_pk(char *path, RSA **rsa)
{
  
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO *rsa_bio = BIO_new(BIO_s_file());
  
  BIO_read_filename(rsa_bio, path);

  if (! PEM_read_bio_RSAPublicKey(rsa_bio, &*rsa, NULL, NULL))
    {
      BIO_printf(out_bio, "\n%s %d %s\n", __FILE__, __LINE__, __func__);      
      ERR_print_errors(out_bio);
      goto err;      
    }
  
 err:
  BIO_free(out_bio);
  BIO_free(rsa_bio);  
  
}


/*
 * RSA *PEM_read_bio_RSAPrivateKey(BIO *bp,
 * RSA **x, pem_password_cb *cb, void *u); */

static void
pem_read_rsa_sk(char *path, RSA **rsa)
{
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO *rsa_bio = BIO_new(BIO_s_file());
  
  BIO_read_filename(rsa_bio, path);

  if (! PEM_read_bio_RSAPrivateKey(rsa_bio, &*rsa, NULL, NULL))
    {
      BIO_printf(out_bio, "\n%s %d %s\n", __FILE__, __LINE__, __func__);      
      ERR_print_errors(out_bio);
      goto err;      
    }
  
 err:
  BIO_free(out_bio);
  BIO_free(rsa_bio);  
  
}


static void
pem_x509_write(X509 *crt)
{
  
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    
  if (! PEM_write_bio_X509(out_bio, crt))
    {    
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
    }
    
  BIO_free(out_bio);
  
}


#endif
