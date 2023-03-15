#ifndef _SFRANK
#define _SFRANK

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <gmp.h>

#define CTX_LEN 32

int send(uint8_t* user_key, uint8_t* msg, int msg_len, int num_servers, uint8_t** write_request_vector);

int process(uint8_t* s, int ct_share_len, uint8_t* h, uint8_t* server_out);

int mod_process(int num_servers, uint8_t* mod_key, uint8_t* ct_share, int ct_share_len, uint8_t* s, uint8_t* context, uint8_t* s_hashes, uint8_t* server_out);

//int read(uint8_t* user_key, int num_servers, uint8_t* shares, int share_len, uint8_t* msg, uint8_t* r, uint8_t* c2, uint8_t* c3, uint8_t* fo);

int read(uint8_t* user_key, int num_servers, uint8_t* shares, int share_len, uint8_t* msg, uint8_t* r, uint8_t* c2_1, uint8_t* ctx, uint8_t* sigma, uint8_t* fo);

//int verify(uint8_t* mod_key, int num_servers, uint8_t* msg, int msg_len, uint8_t* r, uint8_t* c2, uint8_t* c3, uint8_t* fo);

int verify(uint8_t* mod_key, int num_servers, uint8_t* msg, int msg_len, uint8_t* r, uint8_t* c2_1, uint8_t* ctx, uint8_t* sigma, uint8_t* fo);

#endif
