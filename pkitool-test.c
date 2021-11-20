#include "pkitool.h"

#define KEY_PATH "/home/izak/pkitool/secure/server.key"
#define CRT_PATH "/home/izak/pkitool/secure/server.pem"



#define REQ_CRT_PATH "/home/izak/pkitool/secure/client.csr"

int
main()
{

  char *path = "/home/izak/pkitool/secure/test-key.pem";

  PKIT_show_RSA_key(path);
  
  // PKIT_crt_show_key(path);  
  
  // PKIT_csr_new(path);
  
  return 0;
}
