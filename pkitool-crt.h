#ifndef PKITOOL_CRT_H
#define PKITOOL_CRT_H

#include "pkitool-openssl.h"

// X509 *X509_new(void);
static void crt_new(X509 **crt)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  if (! (*crt = X509_new())) {
    BIO_printf(out_bio, "Error creating new X509 object\n");
    goto err;
  }

  if (1 != X509_set_version(*crt, 2)) {
    BIO_printf(out_bio, "Error setting crtificate version\n");
    goto err;
  }

 err:
  BIO_free(out_bio);
  
}


static void crt_write_to_file(char *path, X509 *crt)
{
  BIO *crt_bio;
  BIO *out_bio;  

  crt_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* Write the X509 Certificate to file */
  BIO_write_filename(crt_bio, path);
  if ( ! PEM_write_bio_X509(crt_bio, crt))
    {
      BIO_printf(out_bio, "\nError Writing Certificate\n");
      goto err;
    }
  
 err:
  BIO_free(crt_bio);
}



#if 0

static void crt_read_from_file(char *path, X509 **crt)
{
  BIO *crt_bio;
  BIO *out_bio;  

  crt_bio = BIO_new(BIO_s_file());
  out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_read_filename(crt_bio, path);  ;
  if ( ! (*crt = PEM_read_bio_X509(crt_bio, NULL, NULL, NULL)))
    {
      BIO_printf(out_bio, "\nError Reading Certificate file\n");
      goto err;
    }
  
 err:
  BIO_free(crt_bio);
 
}






// X509_NAME *X509_get_subject_name(const X509 *x);
static void crt_get_subject_name()
{
  
}

// int  X509_set_subject_name(X509 *x, X509_NAME *name)
static void crt_set_subject_name()
{
  
}

//X509_NAME *X509_get_issuer_name(const X509 *x);
static void crt_get_issuer_name()
{
  
}

//int X509_set_issuer_name(X509 *x, X509_NAME *name);
static void crt_set_issuer_name()
{
  
}

#endif // #if 0


#endif
