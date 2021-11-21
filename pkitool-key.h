#ifndef PKITOOL_KEY_H
#define PKITOOL_KEY_H

#include "pkitool-openssl.h"


BN_GENCB *
RSA_generate_keypair_progress_cb()
{
  return NULL;
}

/* int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb); */
static void
key_RSA_generate_keypair(RSA **rsa)
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


/* int PEM_write_bio_RSAPublicKey(BIO *bp, RSA *x); */
static void
key_PEM_write_RSA_public_key(char *path, RSA *rsa)
{
  BIO *key_bio;
  BIO *out_bio;  

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_write_filename(key_bio, path);
  if ( ! PEM_write_bio_RSAPublicKey(key_bio, rsa))    
    {
      BIO_printf(out_bio, "\nError Writing Public Key Key\n");
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
key_PEM_write_RSA_private_key(char *path, RSA *rsa)
{
  BIO *key_bio;
  BIO *out_bio;  

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_write_filename(key_bio, path);
  if ( ! PEM_write_bio_RSAPrivateKey(key_bio, rsa, NULL, NULL, 0, NULL, NULL))    
    {
      BIO_printf(out_bio, "\nError Writing Private Key\n");
      goto err;
    }
  
 err:
  BIO_free(key_bio);
}


static void
key_read_from_pem(char *path, EVP_PKEY **key)
{
  BIO *key_bio;
  BIO *out_bio;  

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_read_filename(key_bio, path);
  if ( ! (*key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL)))
    {
      BIO_printf(out_bio, "\nError Reading Private Key\n");
      goto err;
    }

 err:
  BIO_free(key_bio);
}


#if 0

static void
key_write_to_pem(char *path, EVP_PKEY *key)
{
  BIO *key_bio;
  BIO *out_bio;  

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_write_filename(key_bio, path);
  if ( ! PEM_write_bio_PrivateKey(key_bio, key, NULL, NULL, 0, 0, NULL))    
    {
      BIO_printf(out_bio, "\nError Writing Private Key\n");
      goto err;
    }
  
 err:
  BIO_free(key_bio);

}



static void
key_write_to_file(char *path, EVP_PKEY *key)
{
  BIO *key_bio;
  BIO *out_bio;  

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_write_filename(key_bio, path);
  if ( ! PEM_write_bio_PrivateKey(key_bio, key, NULL, NULL, 0, 0, NULL))    
    {
      BIO_printf(out_bio, "\nError Writing Private Key\n");
      goto err;
    }
  
 err:
  BIO_free(key_bio);

}

#endif // #if 0


#endif
