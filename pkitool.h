#ifndef PKITOOL_H
#define PKITOOL_H

/* Keys */

void PKIT_RSA_generate_keypair(char *pk, char *sk);



/* X509 Certificate */

void PKIT_X509_create(char *pk, char *sk, char *path);
    
void PKIT_X509_REQ_create(char *sk, char *pk, char *path);


#endif
