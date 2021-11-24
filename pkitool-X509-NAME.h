#ifndef PKITOOL_X509_NAME
#define PKITOOL_X509_NAME

#include "pkitool-openssl.h"



/*
 * int X509_NAME_add_entry_by_txt(X509_NAME *name,
 * const char *field, int type, const unsigned char *bytes,
 * int len, int loc, int set); */

static void
x509_name_add_entry_by_txt(X509_NAME *name, const char *field, const unsigned char *bytes)
{
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /*
   * X509_NAME_add_entry_by_txt(), X509_NAME_add_entry_by_OBJ() and X509_NAME_add_entry_by_NID() add
   * a field whose name is defined by a string field, an object obj or a NID nid respectively.
   * The field value to be added is in bytes of length len.
   * If len is -1 then the field length is calculated internally using strlen(bytes). */
  if ( 1 != X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC, bytes, -1, -1, 0))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
      goto err;
    }

 err:
  BIO_free(out_bio);  

}


#endif
