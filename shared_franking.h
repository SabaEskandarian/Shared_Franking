#ifndef _SFRANK
#define _SFRANK

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void ccAEEnc(uint8_t* encKey, uint8_t* msg, int msgLen, uint8_t* iv, uint8_t* c1, uint8_t* c2);
void ccAEDec(uint8_t* encKey,  uint8_t* iv, uint8_t* c1, uint8_t* c2, int msgLen, uint8_t* msg, uint8_t* fo);
void ccAEVerify(uint8_t* msg, int msgLen, uint8_t* c2, uint8_t* fo);

void send(uint8_t* userKey, uint8_t* msg, int msgLen, int numServers, uint8_t* writeRequest_vector);
void process(uint8_t* s, uint8_t* r, int ctShareLen, uint8_t* h, uint8_t* serverOut);
void modProcess(int numServers, uint8_t* modKey, uint8_t* ctShare, int ctShareLen, uint8_t* r);
void read(uint8_t* userKey, int numServers, int shareLen, int contextLen, int msgLen, uint8_t* msg, uint8_t* context, uint8_t* c2, uint8_t* tag, uint8_t* fo, uint8_t* s_vector);
void verify(uint8_t* modKey, int numServers, uint8_t* msg, int msgLen, uint8_t* context, int contextLen, uint8_t* c2, uint8_t* tag, uint8_t* fo, uint8_t* s_vector);

#endif
