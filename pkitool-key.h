#ifndef PKITOOL_KEY_H
#define PKITOOL_KEY_H

#include "pkitool-openssl.h"

static void key_read_from_pem(char *path, EVP_PKEY **key)
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

static void key_read_from_file(const char *path, EVP_PKEY **key)
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


static void key_write_to_file(char *path, EVP_PKEY *key)
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
