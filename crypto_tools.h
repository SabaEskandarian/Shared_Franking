#ifndef _CTOOLS
#define _CTOOLS

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

void printHex(uint8_t* data, int len);
void handleErrors(void);

int ccAEEnc(uint8_t* enc_key, uint8_t* msg, int msg_len, uint8_t* c1_ct, uint8_t* c1_tag, uint8_t* c2);

int ccAEDec(uint8_t* enc_key, uint8_t* c1_ct, int c1_ct_len, uint8_t* c1_tag, uint8_t* c2, uint8_t* msg, uint8_t* fo);

int ccAEVerify(uint8_t* msg, int msg_len, uint8_t* c2, uint8_t* fo);

int prg(uint8_t* seed, uint8_t* output, int output_len);

//expects 32 byte hmac key
int hmac_it(uint8_t* key, const unsigned char *msg, size_t mlen, unsigned char *mac_res);

int verify_hmac(uint8_t* key, const unsigned char *msg, size_t mlen, const unsigned char *val);

void digest_message(const unsigned char *message, size_t message_len, unsigned char *digest);

#endif
