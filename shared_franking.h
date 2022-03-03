#ifndef _SFRANK
#define _SFRANK

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define CTX_LEN 32

int send(uint8_t* user_key, uint8_t* msg, int msg_len, int num_servers, uint8_t** write_request_vector);

int process(uint8_t* s, uint8_t* r, int ct_share_len, uint8_t* h, uint8_t* server_out);

int modProcess(int num_servers, uint8_t* mod_key, uint8_t* ct_share, int ct_share_len, uint8_t* r, uint8_t* context, uint8_t* s_hashes, uint8_t* server_out);

int read(uint8_t* user_key, int num_servers, uint8_t* shares, int share_len, uint8_t* msg, uint8_t* context, uint8_t* c2, uint8_t* tag, uint8_t* fo, uint8_t* s_vector);

int verify(uint8_t* mod_key, int num_servers, uint8_t* msg, int msg_len, uint8_t* context, uint8_t* c2, uint8_t* tag, uint8_t* fo, uint8_t* s_vector);

#endif
