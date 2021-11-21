#include "pkitool.h"

#define RSA_PUBLIC_KEY "/home/izak/pkitool/secure/new_rsa_public_key.pem"
#define RSA_PRIVATE_KEY "/home/izak/pkitool/secure/new_rsa_private_key.pem"


int
main()
{
  
  PKIT_RSA_generate_keypair(RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
  
  PKIT_PEM_print_RSA_pk(RSA_PUBLIC_KEY);
  
  PKIT_PEM_print_RSA_pk(RSA_PRIVATE_KEY);  
  
  return 0;
  
}
