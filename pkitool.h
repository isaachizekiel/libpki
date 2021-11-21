#ifndef PKITOOL_H
#define PKITOOL_H

/* Keys */

void PKIT_RSA_generate_keypair(char *pkpath, char *skpath);


void PKIT_PEM_print_RSA_pk(char *pkpath);


void PKIT_PEM_print_RSA_sk(char *skpath);


#endif
