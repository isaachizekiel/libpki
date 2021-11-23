#include "pkitool.h"

#define RSA_PK_PATH     "/home/izak/pkitool/secure/pk.pem"
#define RSA_SK_PATH     "/home/izak/pkitool/secure/sk.pem"

#define X509_REQ_PATH   "/home/izak/pkitool/secure/X509-req.pem"
#define X509_PATH       "/home/izak/pkitool/secure/X509.pem"

int
main()
{
  
  PKIT_RSA_generate_keypair(RSA_PK_PATH, RSA_SK_PATH);

  PKIT_X509_create(RSA_PK_PATH, RSA_SK_PATH, X509_PATH);

  PKIT_X509_REQ_create(RSA_PK_PATH, RSA_SK_PATH, X509_REQ_PATH);
 
  return 0;
  
}
