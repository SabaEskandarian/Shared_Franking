#include "crypto_tools.h"
#include "shared_franking.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/rand.h>
#include <time.h>

int main()
{
    printf("hello!\n");

    //test PRG
    uint8_t* seed = malloc(16);
    uint8_t* output = malloc(300);

    if(1 != RAND_priv_bytes(seed, 16))
    {
        printf("couldn't get randomness!\n");
        return 1;
    }

    if(1 != prg(seed, output, 300))
    {
        printf("prg fail\n");
        return 1;
    }

    //printHex(output, 300);

    //test HMAC
    uint8_t* hmacKey = malloc(32);
    unsigned char* hmacMsg = "This is the message to HMAC!";
    unsigned char* hmacMsg2 = "This is tha message to HMAC!";
    int mlen = strlen(hmacMsg);
    int mlen2 = strlen(hmacMsg2);
    unsigned long int macLen = 0;
    uint8_t* mac = malloc(32);

    if(1 != RAND_priv_bytes(hmacKey, 32))
    {
        printf("couldn't get randomness!\n");
        return 1;
    }

    if(1 != hmac_it(hmacKey, hmacMsg, mlen, mac))
    {
        printf("HMAC computation failed!\n");
        return 1;
    }

    if(1 != verify_hmac(hmacKey, hmacMsg, mlen, mac))
    {
        printf("HMAC verification failed!\n");
    }

    if(1 == verify_hmac(hmacKey, hmacMsg2, mlen2, mac))
    {
        printf("HMAC failed to catch tampering! Check code.\n");
    }

    free(hmacKey);
    free(mac);

    //test hash
    unsigned char* digestMsg = "This is the message to be hashed";
    uint8_t* digest = malloc(32);
    digest_message(digestMsg, strlen(digestMsg), digest);
    //printHex(digest, 32);
    free(digest);

    //test ccAE
    uint8_t* enc_key = malloc(16);
    unsigned char* msg = "this is the message that will be encrypted";
    int msg_len = strlen(msg);
    uint8_t* c1_ct = malloc(12+msg_len+32);//32 bytes bigger to hold encrypted fo, 12 bytes bigger for iv at beginning
    uint8_t* c1_tag = malloc(16);
    uint8_t* c2 = malloc(32);

    if(1 != RAND_priv_bytes(enc_key, 16))
    {
        printf("couldn't get randomness!\n");
        return 1;
    }

    int ct_len = ccAEEnc(enc_key, msg, msg_len, c1_ct, c1_tag, c2);

    if(ct_len < 1)
    {
        printf("encryption failure\n");
        return 1;
    }

    if(ct_len != 12+msg_len+32)
    {
        printf("something wrong with c1 ct length\n");
        return 1;
    }

    uint8_t* pt = malloc(ct_len - 32 - 12);
    uint8_t* fo = malloc(32);

    int pt_len = ccAEDec(enc_key, c1_ct, ct_len, c1_tag, c2, pt, fo);

    if(pt_len < 1)
    {
        printf("decryption failure\n");
        return 1;
    }


    if(strncmp(msg, pt, pt_len) != 0 || msg_len != pt_len)
    {
        printf("decryption incorrect!\n");
        return 1;
    }

    if(1 != ccAEVerify(pt, pt_len, c2, fo))
    {
        printf("ccAE verification failure\n");
        return 1;
    }


    //check that verification does not accept incorrect message
    if(1 == ccAEVerify(pt, pt_len-1, c2, fo))
    {
        printf("ccAE verification failed to catch message of wrong length\n");
        return 1;
    }

    //now flip a bit and check that the ciphertext fails to decrypt
    c1_ct[0] = c1_ct[0] ^ 1;

    int pt_len_corrupt = ccAEDec(enc_key, c1_ct, ct_len, c1_tag, c2, pt, fo);

    if(pt_len_corrupt > 0)
    {
        printf("didn't catch corrupt CT\n");
        return 1;
    }

    free(enc_key);
    free(c1_ct);
    free(c1_tag);
    free(c2);
    free(pt);
    free(fo);

    //test shared franking

    /*
        int send(uint8_t* user_key, uint8_t* msg, int msg_len, int num_servers, uint8_t** write_request_vector);

        int process(uint8_t* s, uint8_t* r, int ct_share_len, uint8_t* h, uint8_t* server_out);

        int modProcess(int num_servers, uint8_t* mod_key, uint8_t* ct_share, int ct_share_len, uint8_t* r, uint8_t* context, uint8_t* s_hashes, uint8_t* server_out);

        int read(uint8_t* user_key, int num_servers, uint8_t* shares, int share_len, uint8_t* msg, uint8_t* context, uint8_t* c2, uint8_t* tag, uint8_t* fo, uint8_t* s_vector);

        int verify(uint8_t* mod_key, int num_servers, uint8_t* msg, int msg_len, uint8_t* context, uint8_t* c2, uint8_t* tag, uint8_t* fo, uint8_t* s_vector);
     */

    int num_servers_2 = 2;
    int num_servers_5 = 5;
    unsigned char* msg = "This is the message for shared franking.";
    int msg_len = strlen(msg);
    uint8_t* write_request_vector;
    uint8_t* s_hashes = malloc(5*32); //just make it big enough for the bigger test
    uint8_t* server_responses = malloc();



    printf("tests done.\n");

    return 0;
}
