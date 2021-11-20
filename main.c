#include "pkitool.h"

#define KEY_PATH "/home/izak/pkitool/secure/server.key"
#define CRT_PATH "/home/izak/pkitool/secure/server.pem"


#define REQ_CRT_PATH "/home/izak/pkitool/secure/client.csr"

int
main()
{


  
  unsigned char *key_path = "/home/izak/pkitool/secure/test-key.pem";
  PKIT_display_RSA_private_key(key_path);

  PKIT_CSR_from_existing_crt(KEY_PATH, CRT_PATH, REQ_CRT_PATH);

  //PKIT_sign_crt(KEY_PATH, CRT_PATH);
  
  
  return 0;
}
