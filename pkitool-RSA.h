#ifndef PKITOOL_RSA_H
#define PKITOOL_RSA_H

#include "pkitool-openssl.h"


BN_GENCB *
RSA_generate_keypair_progress_cb()
{
  return NULL;
}

/* int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb); */
static void
rsa_generate_keypair(RSA **rsa)
{
  
  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* BN_new() allocates and initializes a BIGNUM structure.
   * BN_secure_new() does the same except that the secure
   * heap OPENSSL_secure_malloc(3) is used to store the value.*/
  BIGNUM *e = BN_new();

  /*
   * BN_zero(), BN_one() and BN_set_word()
   * set a to the values 0, 1 and w respectively.
   * BN_zero() and BN_one() are macros */
  BN_set_word(e, RSA_F4);

  /* RSA_generate_key_ex() generates a 2-prime RSA key pair and
   * stores it in the RSA structure provided in rsa.
   * The pseudo-random number generator must be seeded prior
   * to calling RSA_generate_key_ex(). */
  if (1 != RSA_generate_key_ex(*rsa, 1024, e, NULL))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
      goto err;
    }
  
 err:
  BIO_free(out_bio);
  BN_free(e);
  
}

/*
 * int RSA_check_key(const RSA *rsa);
 * this function uses a deprecated */
static void
rsa_check_key(RSA *rsa)
{

  BIO *out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);;

  /* RSA_check_key_ex() function validates RSA keys.
   * It checks that p and q are in fact prime, and that n = p*q.
   *
   * It does not work on RSA public keys that have only the modulus and public exponent elements populated.
   * It also checks that d*e = 1 mod (p-1*q-1), and that dmp1, dmq1 and iqmp are set correctly or are NULL.
   * It performs integrity checks on all the RSA key material, so the RSA key structure must contain all
   * the private key data too. Therefore, it cannot be used with any arbitrary RSA key object,
   * even if it is otherwise fit for regular RSA operation.*/
  if ( 1 != RSA_check_key(rsa))
    {
      BIO_printf(out_bio, "\nError %s %d %s\n", __FILE__, __LINE__, __func__);
      ERR_print_errors(out_bio);
      goto err;
    }

 err:
  BIO_free(out_bio);
  
}


#endif
