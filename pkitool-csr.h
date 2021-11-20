#ifndef PKITOOL_CSR_H
#define PKITOOL_CSR_H

#include "pkitool-openssl.h"

#if 0


static void csr_read_from_file(char *path, X509_REQ **csr)
{
  BIO *csr_bio;
  BIO *out_bio;  

  csr_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* Load the private Key */
  BIO_read_filename(csr_bio, path);
  if ( ! (*csr = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL)))
    {
      BIO_printf(out_bio, "\nError Reading CSR file\n");
      goto err;
    }
  
 err:
  BIO_free(csr_bio);  
}

static void csr_write_to_file(char *path, X509_REQ *csr)
{
  BIO *csr_bio;
  BIO *out_bio;  

  csr_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* Write the X509 Certificate to file */
  BIO_write_filename(csr_bio, path);
  if ( ! PEM_write_bio_X509_REQ(csr_bio, csr))
    {
      BIO_printf(out_bio, "\nError Writing to CSR file\n");
      goto err;
    }
  
 err:
  BIO_free(csr_bio);
}



//X509_NAME *X509_REQ_get_subject_name(const X509_REQ *req);
static void csr_get_subject_name()
{
  
}


//int X509_REQ_set_subject_name(X509_REQ *req, X509_NAME *name);
static void csr_set_subject_name()
{
  
}

#endif // #if 0

#endif
