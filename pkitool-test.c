#include "pkitool.h"

#define RSA_PATH "/home/izak/pkitool/secure/key.pem"

int
main()
{
  
  PKIT_RSA_generate_keypair(RSA_PATH);
  
  return 0;
  
}
