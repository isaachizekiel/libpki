#include "pkitool-RSA.h"
#include "pkitool-EVP-PKEY.h"
#include "pkitool-PEM.h"
#include "pkitool-X509.h"
#include "pkitool-X509-REQ.h"
#include "pkitool-X509-NAME.h"


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
PKIT_X509_create(char *pk, char *sk, char *path)
{

  /* The X509 ASN1 allocation routines, allocate
   * and free an X509 structure, which
   * represents an X509 certificate.  */  
  X509 *crt = X509_new();

  /* the time which this certificate is valid */
  long valid_secs = 31536000;

  /* creation of the key materials */
  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY *skey = EVP_PKEY_new();

  /* preapare the keys from file to memory
   * in to the EVP_KEY objects */
  pem_read_evp_pk(pk, &pkey);  
  pem_read_evp_sk(sk, &skey);

  /* set the version of the certificate */
  x509_set_version(crt);

  /* set the public key of the certuificate */
  x509_set_pubkey(crt, pkey);

  /* set the expiredate of the certificate */
  x509_set_valid_date(crt, valid_secs);

  /* sign the certificate with our own private key*/
  x509_set_sign(crt, skey);

  /* display the certificate
   * or write it to a file (PEM) */
  pem_x509_write(crt, path);

}


void
PKIT_X509_REQ_create(char *pk, char *sk, char *path)
{

  X509_REQ *req = X509_REQ_new();
  X509_NAME *name = X509_NAME_new();

  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY *skey = EVP_PKEY_new();
  
  pem_read_evp_pk(pk, &pkey);  

  pem_read_evp_sk(sk, &skey);
  
  x509_req_set_version(req, 2);
  
  x509_req_get_subject_name(req, &name);
  
  x509_name_add_entry_by_txt(name, "CN", (const unsigned char *)"HELLO");
  
  x509_req_set_pk(req, pkey);
  
  x509_req_sign(req, skey);

  pem_x509_req_write(req, path);
    
}

