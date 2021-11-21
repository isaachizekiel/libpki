#include "pkitool.h"

#define KEY_PATH "/home/izak/pkitool/secure/server.key"
#define CRT_PATH "/home/izak/pkitool/secure/server.pem"



#define REQ_CRT_PATH "/home/izak/pkitool/secure/client.csr"

#define NEW_CRT_PATH "/home/izak/pkitool/secure/new_crt.pem"

#define NEW_KEY_PATH "/home/izak/pkitool/secure/new_rsa_key.pem"


#define RSA_PUBLIC_KEY "/home/izak/pkitool/secure/new_rsa_public_key.pem"

#define RSA_PRIVATE_KEY "/home/izak/pkitool/secure/new_rsa_private_key.pem"


int
main()
{

  char *path = "/home/izak/pkitool/secure/test-key.pem";

  PKIT_show_RSA_key(path);

  PKIT_crt_new(NEW_CRT_PATH);

  PKIT_generate_RSA_keypair(RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);

  // PKIT_crt_show_key(path);  
  
  // PKIT_csr_new(path);
  
  return 0;
}
