#include "pkitool.h"

#define RSA_PK "/home/izak/pkitool/secure/new_rsa_pk.pem"
#define RSA_SK "/home/izak/pkitool/secure/new_rsa_sk.pem"


int
main()
{
  
  PKIT_RSA_generate_keypair(RSA_PK, RSA_SK);
  
  PKIT_PEM_print_RSA_pk(RSA_PK);
  
  PKIT_PEM_print_RSA_sk(RSA_SK);  
  
  return 0;
  
}
