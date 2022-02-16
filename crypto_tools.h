#ifndef _CTOOLS
#define _CTOOLS

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


int prg(uint8_t* seed, uint8_t* output, int outputLen);

//From the openSSL documentation
void handleErrors(void);
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

int hmac_it(const unsigned char *msg, size_t mlen, unsigned char **val, size_t *vlen, EVP_PKEY *pkey);

int verify_it(const unsigned char *msg, size_t mlen, const unsigned char *val, size_t vlen, EVP_PKEY *pkey);

void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len);

#endif
