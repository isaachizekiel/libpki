#include <iostream>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define CRT_PATH "/home/izak/openssl-sign-by-ca/example/server.pem"
#define KEY_PATH "/home/izak/openssl-sign-by-ca/example/server.key"

#define CA_CRT_PATH "/home/izak/openssl-sign-by-ca/example/server.pem"
#define CA_KEY_PATH "/home/izak/openssl-sign-by-ca/example/server.key"

class LibPKI {

public:

  ~LibPKI()
  {
    EVP_PKEY_free(key);
    //EVP_PKEY_free(ca_privkey);
    X509_REQ_free(crt_req);
    X509_free(crt);
    //BIO_free_all(reqbio);
    BIO_free_all(out_bio);
  }
  
  LibPKI()
  {
    /**
     * necessary evil
     */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /**
     * Initialize BIOs
     */
    ca_crt_bio = BIO_new(BIO_s_file());
    ca_key_bio = BIO_new(BIO_s_file());
    crt_bio = BIO_new(BIO_s_file());
    key_bio = BIO_new(BIO_s_file());
    out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  }

  void create_csr()
  {
    int ret = 0;
    
    /**
     * Load the old certificate
     */
    ret = BIO_read_filename(crt_bio, CRT_PATH);
    crt = PEM_read_bio_X509(crt_bio, nullptr, nullptr, nullptr);
    if (!crt)
      {
	BIO_printf(out_bio, "\nError loading Certificate\n");
	return;
      }

    /**
     * Load the old private key
     */
    ret = BIO_read_filename(key_bio, KEY_PATH);
    key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    if (!key)
      {
	BIO_printf(out_bio, "\nError loading Private Key\n");
      }

    /**
     * Load the old Certificate in to a new Request
     */

    crt_req = X509_to_X509_REQ(crt, key, EVP_sha256());
    if (crt_req == nullptr)
      {
	BIO_printf(out_bio, "\nError converting certificate in to request\n");
      }
    
    /**
     * Print the request
     */
    PEM_write_bio_X509_REQ(out_bio, crt_req);

  }

  void sign_certificate()
  {
    int ret = 0;
    
    /**
     * Load the request data from the crt
     * This function assumes that crt_req is initalized
     */
    //req_bio = BIO_new_mem_buf(req_str, -1);
    //crt_req = PEM_read_bio_X509_REQ(req_bio, nullptr, nullptr, nullptr);
    // this is already loaded in the csr
    if (!crt_req)
      {
	BIO_printf(out_bio, "\nError can not read Certificate Request data\n");
	return;
      }

    /**
     * Load the CA Certificate
     */
    BIO_read_filename(ca_crt_bio, CA_CRT_PATH);
    if (!(ca_crt = PEM_read_bio_X509(ca_crt_bio, nullptr, nullptr, nullptr)))
      {
	BIO_printf(out_bio, "\nError loading CA Certificate\n");
	return;
      }
    
    /**
     * Load the CA Private Key
     */
    ret = BIO_read_filename(ca_key_bio, CA_KEY_PATH);
    ca_key = PEM_read_bio_PrivateKey(ca_key_bio, nullptr, nullptr, nullptr);
    if (!crt)
      {
	BIO_printf(out_bio, "\nError loading CA Private Key\n");
	return;
      }
    

    /**
     * Create a Certificate from the request
     */
    if (!X509_new())
      {
	BIO_printf(out_bio, "\nError Creating X509 Object\n");
	return;
      }

    /**
     * Set version to X509v3
     */
    if (1 != X509_set_version(crt, 2))
      {
	BIO_printf(out_bio, "\nError Setting Certificate version\n");
	return;
      }

    /**
     * Set the certificate serial number
     */
    serial = ASN1_INTEGER_new();
    ASN1_INTEGER_set(serial, 0);
    if(!X509_set_serialNumber(crt, serial))
      {
	BIO_printf(out_bio, "\nError Setting Serial Number\n");
	return;
      }
    
    /**
     * Extract the Subject name from the request
     */
    if (!(name = X509_REQ_get_subject_name(crt_req)))
      {
	BIO_printf(out_bio, "\nError getting the Subject Name\n");
	return;
      }
    
    /**
     * Set the new Certificate Subject Name
     */
    if (1 != X509_set_subject_name(crt, name))
      {
	BIO_printf(out_bio, "\nError Setting Subject Name\n");
	return;
      }

    
    /**
     * Extract the Subject Name from the CA Certificate
     */
    
    if (!(name = X509_get_subject_name(ca_crt)))
      {
	BIO_printf(out_bio, "\nError Extracting Subject Name from the CA Certificate\n");
	return;
      }


    /**
     * Set the new Certificate Issuer name
     */

    if (1 != X509_set_issuer_name(crt, name))
      {
	BIO_printf(out_bio, "\nError Setting Issuer Name\n");
	return;
      }

    
    /**
     * Extract the public key
     */
    if (! (req_pub_key = X509_REQ_get_pubkey(crt_req)))
      {
	BIO_printf(out_bio, "\nError extracting Public key from the Request\n");
	return;
      }

    /**
     * Use the above public key to verify the Signature
     */
    if (1 != X509_REQ_verify(crt_req, req_pub_key))
      {
	BIO_printf(out_bio, "\nError Verifying Signature\n");
	return;
      }
    
    /**
     * Set the new Certificate Public Key
     */
    if (1 != X509_set_pubkey(crt, req_pub_key))
      {
	BIO_printf(out_bio, "\nError Setting Public Key of the Certificate\n");
	return;
      }

    /**
     * Set the Lifetime of the Certificate
     */     
    if (!X509_gmtime_adj(X509_get_notBefore(crt), 0))
      {
	BIO_printf(out_bio, "\nError Setting the start time\n");
	return;
      }

    if (!X509_gmtime_adj(X509_get_notAfter(crt), valid_secs))
      {
	BIO_printf(out_bio, "\nError Setting the End date\n");
	return;
      }


    /**
     * Add X509V3 Extensions
     */
    /*
    X509V3_set_ctx(x509V3Ctx, ca_crt, crt, nullptr, nullptr, nullptr);
    if (!ret)
      {
	BIO_printf(out_bio, "\nWarning Setting X509V3 Extension\n");
      }
    */

    
    /**
     * Sign digest type, sign new Certificate with CA's Private Key
     */
    if (!X509_sign(crt, ca_key, EVP_sha256()))
      {
	BIO_printf(out_bio, "\nError Signing the new Certificate\n");
	return;
      }
    
    /**
     * Print the Certificate
     */
    if (!PEM_write_bio_X509(out_bio, crt))
      {
	BIO_printf(out_bio, "\nError Printing the Signed Certificate\n");
	return;
      }
    
    }
  
private:
  
  ASN1_INTEGER    *serial = nullptr;
  X509_NAME       *name;
  X509V3_CTX      *x509V3Ctx;
  X509_EXTENSION  *extension;
  long            valid_secs = 31536000; // 365 days
  
  
  BIO             *crt_bio = nullptr;
  BIO             *key_bio = nullptr;
  BIO             *out_bio = nullptr;
  BIO             *req_bio = nullptr;
  BIO             *ca_crt_bio = nullptr;
  BIO             *ca_key_bio = nullptr;
  X509_REQ        *crt_req = nullptr;
  X509            *crt = nullptr, *ca_crt = nullptr;
  EVP_PKEY        *key = nullptr, *ca_key = nullptr;
  EVP_PKEY        *pub_key = nullptr, *req_pub_key = nullptr;

  char req_str[10] = {0};
  
};

int main() {
  auto libPki = LibPKI();
  libPki.create_csr();
  libPki.sign_certificate();
  return 0;
}
