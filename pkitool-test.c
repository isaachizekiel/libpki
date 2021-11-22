#include "pkitool.h"

#define EVP_PKEY_PATH "/home/izak/pkitool/secure/key.pem"

int
main()
{
  
  PKIT_EVP_PKEY_generate_RSA_keypair(EVP_PKEY_PATH);
  
  return 0;
  
}
