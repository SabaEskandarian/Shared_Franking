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

    printHex(output, 300);

    return 0;
}
