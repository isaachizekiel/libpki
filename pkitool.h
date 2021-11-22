#ifndef PKITOOL_H
#define PKITOOL_H

/* Keys */

void PKIT_RSA_generate_keypair(char *pkpath, char *skpath);

void PKIT_EVP_PKEY_generate_RSA_keypair(char *path);

/* Depricated */
void PKIT_PEM_print_RSA_pk(char *pkpath);
void PKIT_PEM_print_RSA_sk(char *skpath);




#endif
