#include "pkitool-key.h"
#include "pkitool-crt.h"
#include "pkitool-crl.h"
#include "pkitool-csr.h"
#include "pkitool-io.h"

#include "pkitool.h"

/*
 * Keys
 */

void PKIT_generate_RSA_keypair(char *public, char *private)
{
  
  /* Initialize the PrivateKey */
  RSA *rsa = RSA_new();
  //EVP_PKEY *key = EVP_PKEY_new();

  /* Generate the rsa key */
  key_RSA_generate_keypair(&rsa);

  /* Writes the RSA public key to PEM */
  key_PEM_write_RSA_public_key(public, rsa);

  /* Writes the RSA private key to PEM */
  key_PEM_write_RSA_private_key(private, rsa);

  /* Free the RSA Object */
  RSA_free(rsa);
  
}



void PKIT_show_RSA_key(char *path)
{

  BIO *key_bio;
  BIO *out_bio;
  EVP_PKEY *key;
  RSA *rsa_key;

  /* Setting up the basics */
  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* Read the file into the key_bio*/
  BIO_read_filename(key_bio, path);

  /* Read the key from the loaded PEM format */
  key_read_from_pem(path, &key);
  
  /* Check if our rsa is valid */
  rsa_key = EVP_PKEY_get1_RSA(key);
  if ( ! RSA_check_key(rsa_key))
    {
      BIO_printf(out_bio, "\nError Validating RSA Key\n");
      goto err;
    }
  
  /* Print the Certificate in PEM format */    
  PEM_write_bio_PrivateKey(out_bio, key, NULL, NULL, 0, NULL, NULL);

 err:
  BIO_free(out_bio);
  BIO_free(key_bio);
  EVP_PKEY_free(key);
  RSA_free(rsa_key);
  
}


/*
 * Certificates */
void
PKIT_crt_show_key(char *path)
{
  //EVP_PKEY *key;
  //BIO *bio_out;
  
  
  //RSA *rsakey;
  
  //crt_read_key_from_file(path, &key);
  //read_key_from_file(path, &key);
}


void
PKIT_crt_new(char *path)
{
  
  X509 *crt;
  
  crt_new(&crt);
  
  crt_write_to_file(path, crt);
  
  X509_free(crt);
  
}


void
PKIT_csr_new(char *path)
{
  
}
