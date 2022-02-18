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

    unsigned char* digestMsg = "This is the message to be hashed";
    uint8_t* digest = malloc(32);
    digest_message(digestMsg, strlen(digestMsg), digest);
    //printHex(digest, 32);
    free(digest);

    printf("tests done.\n");

    return 0;
}
