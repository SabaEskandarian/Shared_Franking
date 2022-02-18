#include "crypto_tools.h"
#include "shared_franking.h"

#include <openssl/rand.h>

//TODO

void ccAEEnc(uint8_t* encKey, uint8_t* msg, int msgLen, uint8_t* iv, uint8_t* c1, uint8_t* c2)
{
    return;
}

void ccAEDec(uint8_t* encKey,  uint8_t* iv, uint8_t* c1, uint8_t* c2, int msgLen, uint8_t* msg, uint8_t* fo)
{
    return;
}

void ccAEVerify(uint8_t* msg, int msgLen, uint8_t* c2, uint8_t* fo)
{
    return;
}
