#ifndef PKITOOL_X509_NAME
#define PKITOOL_X509_NAME

#include "pkitool-openssl.h"


//X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);

//X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);

//X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);

//X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);

//X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);



/*
 * int X509_NAME_add_entry_by_txt(X509_NAME *name,
 * const char *field, int type, const unsigned char *bytes,
 * int len, int loc, int set); */

static void
x509_name_add_entry_by_txt(X509_NAME *name, const char *field, const unsigned char *bytes)
{
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  
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
