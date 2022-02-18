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
    unsigned char* hmacMsg2 = "This is the wrong message to HMAC!";
    int mlen = strlen(hmacMsg);
    int mlen2 = strlen(hmacMsg2);
    unsigned long int macLen = 0;
    uint8_t* mac;

    if(1 != RAND_priv_bytes(hmacKey, 32))
    {
        printf("couldn't get randomness!\n");
        return 1;
    }

    if(1 != hmac_it(hmacKey, hmacMsg, mlen, &mac, &macLen))
    {
        printf("HMAC computation failed!\n");
        return 1;
    }

    if(1 != verify_it(hmacKey, hmacMsg, mlen, mac, macLen))
    {
        printf("HMAC verification failed!\n");
    }

    if(1 == verify_it(hmacKey, hmacMsg2, mlen2, mac, macLen))
    {
        printf("HMAC failed to catch tampering! Check code.\n");
    }

    printf("tests done.\n");

    return 0;
}
