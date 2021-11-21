#ifndef PKITOOL_H
#define PKITOOL_H


/* Keys */

void PKIT_generate_RSA_keypair(char *public, char *private);

void PKIT_show_RSA_key(char *path);



/* Certificates */

void PKIT_crt_new(char *path);

void PKIT_crt_show_key(char *path);
  

/* Certificate Signing Requests */

void PKIT_csr_new(char *path);

#endif
