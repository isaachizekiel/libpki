#ifndef PKITOOL_PEM_H
#define PKITOOL_PEM_H

#include "pkitool-openssl.h"


/*  
 * RSA *PEM_read_bio_RSAPublicKey(BIO *bp, RSA **x,
 * pem_password_cb *cb, void *u); */

static void
pem_read_rsa_pk(char *path, RSA *rsa)
{

  BIO *key_bio;
  BIO *out_bio;  

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_write_filename(key_bio, path);
  if ( ! PEM_read_bio_RSAPublicKey(key_bio, &rsa, NULL, NULL))    
    {
      BIO_printf(out_bio, "\nError Reading Public Key\n");
      goto err;
    }
  
 err:
  BIO_free(key_bio);
  
}

/* int PEM_write_bio_RSAPublicKey(BIO *bp, RSA *x); */

static void
pem_write_rsa_pk(char *path, RSA *rsa)
{

  BIO *key_bio;
  BIO *out_bio;  

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_write_filename(key_bio, path);
  if ( 1 != PEM_write_bio_RSAPublicKey(key_bio, rsa))    
    {
      BIO_printf(out_bio, "\nError Writing Public Key\n");
      goto err;
    }
  
 err:
  BIO_free(key_bio);
  
}

/* int PEM_write_bio_RSAPublicKey(BIO *bp, RSA *x); */

static void
pem_print_rsa_pk(RSA *rsa)
{

  BIO *out_bio;  

  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  if ( 1 != PEM_write_bio_RSAPublicKey(out_bio, rsa))    
    {
      BIO_printf(out_bio, "\nError Priniting Public Key\n");
      goto err;
    }
  
 err:
  BIO_free(out_bio);
  
}

/*
 * RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x,
 * pem_password_cb *cb, void *u); */

static void
pem_read_rsa_sk(char *path, RSA *rsa)
{

  BIO *key_bio;
  BIO *out_bio;  

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_write_filename(key_bio, path);
  if ( ! PEM_read_bio_RSAPrivateKey(key_bio, &rsa, NULL, NULL ))
    {
      BIO_printf(out_bio, "\nError Reading Private Key\n");
      goto err;
    }
  
 err:
  BIO_free(key_bio);
  
}

/*
 * int PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *x,
 * const EVP_CIPHER *enc, unsigned char *kstr, int klen,
 * pem_password_cb *cb, void *u); */

static void
pem_write_rsa_sk(char *path, RSA *rsa)
{

  BIO *key_bio;
  BIO *out_bio;  

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_write_filename(key_bio, path);
  if ( 1 != PEM_write_bio_RSAPrivateKey(key_bio, rsa, NULL, NULL, 0, NULL, NULL))    
    {
      BIO_printf(out_bio, "\nError Writing Private Key\n");
      goto err;
    }
  
 err:
  BIO_free(key_bio);
  
}

/*
 * int PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *x,
 * const EVP_CIPHER *enc, unsigned char *kstr, int klen,
 * pem_password_cb *cb, void *u); */

static void
pem_print_rsa_sk(RSA *rsa)
{

  BIO *out_bio;  

  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  if ( 1 != PEM_write_bio_RSAPrivateKey(out_bio, rsa, NULL, NULL, 0, NULL, NULL))    
    {
      BIO_printf(out_bio, "\nError Printing Private Key\n");
      goto err;
    }
  
 err:
  BIO_free(out_bio);
  
}


#endif
