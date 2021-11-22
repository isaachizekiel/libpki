#ifndef PKITOOL_H
#define PKITOOL_H

/* Keys */

void PKIT_RSA_generate_keypair(char *pk, char *sk);



/* X509 Certificate */

void PKIT_X509_create_certificate(char *pk, char *sk);
    


#endif
