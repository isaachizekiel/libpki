#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/objects.h> /* RSA */
#include <openssl/x509v3.h>


static void read_key_from_file(unsigned char *key_path, EVP_PKEY **key)
{
  BIO *key_bio;
  BIO *out_bio;  

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* Load the private Key */
  BIO_read_filename(key_bio, key_path);  ;
  if ( ! (*key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL)))
    {
      BIO_printf(out_bio, "\nError Loading Private Key\n");
      goto err;
    }

 err:
  BIO_free(key_bio);
}


static void read_crt_from_file(unsigned char *crt_path, X509 **crt)
{
  BIO *crt_bio;
  BIO *out_bio;  

  crt_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* Load the private Key */
  BIO_read_filename(crt_bio, crt_path);  ;
  if ( ! (*crt = PEM_read_bio_X509(crt_bio, NULL, NULL, NULL)))
    {
      BIO_printf(out_bio, "\nError Loading Private Key\n");
      goto err;
    }
  
 err:
  BIO_free(crt_bio);
 
}

static void write_key_to_file(unsigned char *key_path, EVP_PKEY *key)
{
  BIO *key_bio;
  BIO *out_bio;  

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_write_filename(key_bio, key_path);
  if ( ! PEM_write_bio_PrivateKey(key_bio, key, NULL, NULL, 0, 0, NULL))    
    {
      BIO_printf(out_bio, "\nError Loading Private Key\n");
      goto err;
    }
  
 err:
  BIO_free(key_bio);

}

static void write_crt_to_file(unsigned char *crt_path, X509 *crt)
{
  BIO *crt_bio;
  BIO *out_bio;  

  crt_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* Write the X509 Certificate to file */
  BIO_write_filename(crt_bio, crt_path);
  if ( ! PEM_write_bio_X509(crt_bio, crt))
    {
      BIO_printf(out_bio, "\nError Loading Private Key\n");
      goto err;
    }
  
 err:
  BIO_free(crt_bio);
}


static void write_csr_to_file(unsigned char *csr_path, X509_REQ *csr)
{
  BIO *csr_bio;
  BIO *out_bio;  

  csr_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* Write the X509 Certificate to file */
  BIO_write_filename(csr_bio, csr_path);
  if ( ! PEM_write_bio_X509_REQ(csr_bio, csr))
    {
      BIO_printf(out_bio, "\nError Loading Private Key\n");
      goto err;
    }
  
 err:
  BIO_free(csr_bio);
}



/*
 * The begining of the tool's API
 */

void PKIT_display_RSA_private_key(unsigned char *key_path)
{
  EVP_PKEY *key;
  BIO *key_bio;  
  BIO *out_bio;
  RSA *rsa_key;

  key_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* load the key */
  read_key_from_file(key_path, &key);
  
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


/* Create a new CSR request from X509 certificate */
void PKIT_CSR_from_existing_crt(unsigned char *key_path, unsigned char *crt_path, unsigned char *csr_path)
{  
  BIO       *crt_bio;
  BIO       *key_bio;
  BIO       *out_bio;

  X509      *crt;
  X509_REQ  *crt_req;

  EVP_PKEY  *key;


  /* Initialize the basics */
  key_bio = BIO_new(BIO_s_file());
  crt_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  
  /* Load the Key in to memory */
  read_key_from_file(key_path, &key);

  /* Load the Certificate in to memory */
  read_crt_from_file(crt_path, &crt);

  /* Convert the old certificate in to the new request */
  if ( ! (crt_req = X509_to_X509_REQ(crt, key, EVP_sha256())))
    {
      BIO_printf(out_bio, "\nError Loading the X509 Certificate\n");
      goto err;
    }

  /* Print the certificate */
  PEM_write_bio_X509_REQ(out_bio, crt_req);

  write_csr_to_file(csr_path, crt_req);
  
 err:  
  BIO_free(crt_bio);
  BIO_free(key_bio);
  BIO_free(out_bio);
  X509_free(crt);
  X509_REQ_free(crt_req);
  EVP_PKEY_free(key);
  
}


/* create a new certificate */
void PKIT_sign_crt(unsigned char *ca_key_path, unsigned char* ca_crt_path, unsigned char *req_path)
{
  unsigned char  request_str[] = {};

  BIO            *req_bio;
  BIO            *out_bio;
  BIO            *crt_bio;
  BIO            *key_bio;
  X509           *crt;
  X509_REQ       *crt_req;

  ASN1_INTEGER   *serial;
  EVP_PKEY       *ca_key, *req_pub_key;
  X509           *new_crt, *ca_crt;
  X509_NAME      *name;
  X509V3_CTX     ctx;
  FILE           *fp;
  long           valid_secs = 31536000;



  /* Create the Input/Output BIO's.*/
  out_bio  = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* Load the request data in a BIO, then in a x509_REQ struct. */
  req_bio = BIO_new_mem_buf(request_str, -1);
  if (! (crt_req = PEM_read_bio_X509_REQ(req_bio, NULL, NULL, NULL))) {
    BIO_printf(out_bio, "Error can't read X509 request data into memory\n");
    goto err;
   }

  
    /* Load the Key file in to OpenSSL's Secure IO */  
  BIO_read_filename(key_bio, ca_key_path);
  if ( ! (ca_key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL)))
    {
      BIO_printf(out_bio, "\nError Loading the Privatekey\n");
      goto err;      
    }


  /* Load the Certificate file in to OpenSSL's Secure IO */
  BIO_read_filename(crt_bio, ca_crt_path);
  if ( ! (ca_crt = PEM_read_bio_X509(crt_bio, NULL, NULL, NULL)))
    {
      BIO_printf(out_bio, "\nError Loading the X509 Certificate\n");
      goto err;
    }

  
  if (! (crt_req = PEM_read_bio_X509_REQ(req_bio, NULL, NULL, NULL))) {
    BIO_printf(out_bio, "Error can't read X509 request data into memory\n");
    goto err;
  }
  

  /* Build Crtificate with data from request */
  if (! (new_crt=X509_new())) {
    BIO_printf(out_bio, "Error creating new X509 object\n");
    goto err;
   }

  if (X509_set_version(new_crt, 2) != 1) {
    BIO_printf(out_bio, "Error setting crtificate version\n");
    goto err;
   }


  /* set the crtificate serial number here
   * If there is a problem, the value defaults to '0' */
  serial = ASN1_INTEGER_new();
  ASN1_INTEGER_set(serial, 0);
  if (! X509_set_serialNumber(new_crt, serial)) {
    BIO_printf(out_bio, "Error setting serial number of the crtificate\n");
    goto err;
   }


  /* Extract the subject name from the request */
  if (! (name = X509_REQ_get_subject_name(crt_req)))
    BIO_printf(out_bio, "Error getting subject from crt request\n");


  /* Set the new crtificate subject name */   
  if (X509_set_subject_name(new_crt, name) != 1) {
    BIO_printf(out_bio, "Error setting subject name of crtificate\n");
    goto err;
   }


  /* Extract the subject name from the signing CA crt */
  if (! (name = X509_get_subject_name(ca_crt))) {
    BIO_printf(out_bio, "Error getting subject from CA crtificate\n");
    goto err;
   }


  /* Set the new crtificate issuer name */
  if (X509_set_issuer_name(new_crt, name) != 1) {
    BIO_printf(out_bio, "Error setting issuer name of crtificate\n");
    goto err;
   }


  /* Extract the public key data from the request */
  if (! (req_pub_key=X509_REQ_get_pubkey(crt_req))) {
    BIO_printf(out_bio, "Error unpacking public key from request\n");
    goto err;
   }


  /* Optionally: Use the public key to verify the signature */
  if (X509_REQ_verify(crt_req, req_pub_key) != 1) {
    BIO_printf(out_bio, "Error verifying signature on request\n");
    goto err;
   }

  /* Set the new crtificate public key */
  if (X509_set_pubkey(new_crt, req_pub_key) != 1) {
    BIO_printf(out_bio, "Error setting public key of crtificate\n");
    goto err;
   }


  /* Set X509V3 start date (now) and expiration date (+365 days) */
   if (! (X509_gmtime_adj(X509_get_notBefore(new_crt),0))) {
      BIO_printf(out_bio, "Error setting start time\n");
    goto err;
   }

   if(! (X509_gmtime_adj(X509_get_notAfter(new_crt), valid_secs))) {
      BIO_printf(out_bio, "Error setting expiration time\n");
    goto err;
   }

  /* Add X509V3 extensions */
  X509V3_set_ctx(&ctx, ca_crt, new_crt, NULL, NULL, 0);
  X509_EXTENSION *ext;


  /* Set digest type, sign new crtificate with CA's private key */
  if (! X509_sign(new_crt, ca_key, EVP_sha256())) {
    BIO_printf(out_bio, "Error signing the new crtificate\n");
    goto err;
   }


  /* print the crtificate */
  if (! PEM_write_bio_X509(out_bio, new_crt)) {
    BIO_printf(out_bio, "Error printing the signed crtificate\n");
    goto err;
   }

  
  /* Free up all structures */
 err:  
  EVP_PKEY_free(req_pub_key);
  EVP_PKEY_free(ca_key);
  X509_REQ_free(crt_req);
  X509_free(new_crt);
  BIO_free_all(req_bio);
  BIO_free_all(out_bio);

  
}
