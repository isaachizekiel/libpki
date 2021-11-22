#include "pkitool-key-rsa.h"
#include "pkitool-evp-pkey.h"
#include "pkitool-pem.h"

#include "pkitool-cert.h"
#include "pkitool-cert-req.h"

#include "pkitool.h"

/*
 * Keys
 */

void
PKIT_RSA_generate_keypair(char *pk, char *sk)
{

  /* Init the basic datastructures */
  RSA *rsa = RSA_new();
  EVP_PKEY *key = EVP_PKEY_new();

  /* Begin by generating the key pair */
  rsa_generate_keypair(&rsa);

  /* check weather our rsa keypair is valid */
  rsa_check_key(rsa);

  /* assigns RSA object to EVP_PKEY object */
  evp_pkey_assign_rsa(&key, rsa);

  /* This function can make output the
   * PEM encoded object to any given file discreptor
   * the stdout or file or  ... */
  pem_write_evp_pk(pk, key);

  /* see the above comment */
  pem_write_evp_sk(sk, key);

  /* When key is freed rsa is also freed
   * because the EVP_PKEY_assign_RSA is executed
   * both objects will be pointed by the same pointer
   * when one one of them is free both will become free */
  EVP_PKEY_free(key);
    
}

/*
 * Certificates */
void
PKIT_X509_create_certificate(char *pk, char *sk)
{
  
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);  
  X509 *crt = X509_new();
  //X509_NAME *name = "izak";
  
  long valid_secs = 31536000;

  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY *skey = EVP_PKEY_new();
  
  pem_read_evp_pk(pk, &pkey);  
  pem_read_evp_sk(sk, &skey);

  
  if (1 != X509_set_version(crt, 2))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
    }

  if (1 != X509_set_pubkey(crt, pkey))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
    }


  if (! (X509_gmtime_adj(X509_get_notBefore(crt),0)))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
    }

  
  if(! (X509_gmtime_adj(X509_get_notAfter(crt), valid_secs)))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
    }
  
  
  
  if (! X509_sign(crt, skey, EVP_sha256()))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);    
    }


  if (! PEM_write_bio_X509(out_bio, crt))
    {    
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
    }

}

