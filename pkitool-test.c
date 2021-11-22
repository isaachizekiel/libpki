#include "pkitool.h"

#define RSA_PK_PATH "/home/izak/pkitool/secure/pk.pem"
#define RSA_SK_PATH "/home/izak/pkitool/secure/sk.pem"

int
main()
{
  
  PKIT_RSA_generate_keypair(RSA_PK_PATH, RSA_SK_PATH);

  PKIT_X509_create_certificate(RSA_PK_PATH, RSA_SK_PATH);

  return 0;
  
}
