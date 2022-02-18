#include "crypto_tools.h"
#include "shared_franking.h"

#include <openssl/rand.h>

/*
 int prg(uint8_t* seed, uint8_t* output, int outputLen);
void printHex(uint8_t* data, int len);
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
//expects 32 byte hmac key
int hmac_it(uint8_t* key, const unsigned char *msg, size_t mlen, unsigned char *macRes);
int verify_hmac(uint8_t* key, const unsigned char *msg, size_t mlen, const unsigned char *val);
void digest_message(const unsigned char *message, size_t message_len, unsigned char *digest);
 */


//TODO write tests for the ccAE functions after they're done before moving on to actual scheme.
//iv size is 12
//c1_ct size is msg_len
//c1_tag size is 16
//c2 size is 32
int ccAEEnc(uint8_t* enc_key, uint8_t* msg, int msg_len, uint8_t* iv, uint8_t* c1_ct, uint8_t* c1_tag, uint8_t* c2)
{

        //TODO HMAC key needs to be appended to plaintext before encryption
        //maybe don't use the gcm_encrypt function and do this directly via openssl

        //get 32 bytes of commitment randomness which will serve as an HMAC key
        uint8_t* hmac_key = malloc(32);
        if(1 != RAND_priv_bytes(hmac_key, 32))
        {
            printf("couldn't get randomness!\n");
            return 0;
        }

        //produce the commitment c2, which is an hmac of the message
        if(1 != hmac_it(hmac_key, msg, msg_len, c2))
        {
            printf("failed to HMAC\n");
            return 0;
        }

        //use provided IV for encryption
        //encrypt message with hmac as the aad
        int c1_ct_len = gcm_encrypt(msg, msg_len, c2, 32, enc_key, iv, 12, c1_ct, c1_tag);

        if(c1_ct_len != msg_len)
        {
            printf("something wrong with c1 ct length\n");
            return 0;
        }
}

int ccAEDec(uint8_t* enc_key,  uint8_t* iv, uint8_t* c1, uint8_t* c1_tag, uint8_t* c2, int msgLen, uint8_t* msg, uint8_t* fo)
{
    return 0;
}

int ccAEVerify(uint8_t* msg, int msg_len, uint8_t* c2, uint8_t* fo)
{
    return 0;
}
