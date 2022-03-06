#include "crypto_tools.h"
#include "shared_franking.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/rand.h>
#include <time.h>


int basic_crypto_tests()
{
    //test PRG
    uint8_t* seed = malloc(16);
    uint8_t* output = malloc(300);

    if(1 != RAND_priv_bytes(seed, 16))
    {
        printf("couldn't get randomness!\n");
        return 0;
    }

    if(1 != prg(seed, output, 300))
    {
        printf("prg fail\n");
        return 0;
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
        return 0;
    }

    if(1 != hmac_it(hmacKey, hmacMsg, mlen, mac))
    {
        printf("HMAC computation failed!\n");
        return 0;
    }

    if(1 != verify_hmac(hmacKey, hmacMsg, mlen, mac))
    {
        printf("HMAC verification failed!\n");
        return 0;
    }

    if(1 == verify_hmac(hmacKey, hmacMsg2, mlen2, mac))
    {
        printf("HMAC failed to catch tampering! Check code.\n");
        return 0;
    }

    free(hmacKey);
    free(mac);

    //test hash
    unsigned char* digestMsg = "This is the message to be hashed";
    uint8_t* digest = malloc(32);
    digest_message(digestMsg, strlen(digestMsg), digest);
    //printHex(digest, 32);
    free(digest);

    return 1;
}

int ccAE_tests()
{
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
        return 0;
    }

    int ct_len = ccAEEnc(enc_key, msg, msg_len, c1_ct, c1_tag, c2);

    if(ct_len < 1)
    {
        printf("encryption failure\n");
        return 0;
    }

    if(ct_len != 12+msg_len+32)
    {
        printf("something wrong with c1 ct length\n");
        return 0;
    }

    uint8_t* pt = malloc(ct_len - 32 - 12);
    uint8_t* fo = malloc(32);

    int pt_len = ccAEDec(enc_key, c1_ct, ct_len, c1_tag, c2, pt, fo);

    if(pt_len < 1)
    {
        printf("decryption failure\n");
        return 0;
    }


    if(strncmp(msg, pt, pt_len) != 0 || msg_len != pt_len)
    {
        printf("decryption incorrect!\n");
        return 0;
    }

    if(1 != ccAEVerify(pt, pt_len, c2, fo))
    {
        printf("ccAE verification failure\n");
        return 0;
    }


    //check that verification does not accept incorrect message
    if(1 == ccAEVerify(pt, pt_len-1, c2, fo))
    {
        printf("ccAE verification failed to catch message of wrong length\n");
        return 0;
    }

    //now flip a bit and check that the ciphertext fails to decrypt
    c1_ct[0] = c1_ct[0] ^ 1;

    int pt_len_corrupt = ccAEDec(enc_key, c1_ct, ct_len, c1_tag, c2, pt, fo);

    if(pt_len_corrupt > 0)
    {
        printf("didn't catch corrupt CT\n");
        return 0;
    }

    free(enc_key);
    free(c1_ct);
    free(c1_tag);
    free(c2);
    free(pt);
    free(fo);

    return 1;
}

int shared_franking_tests()
{

    //test shared franking

    int max_servers = 10;
    unsigned char* msg = "This is the message for shared franking.";
    int msg_len = strlen(msg);
    uint8_t* write_request_vector;
    uint8_t* s_hashes = malloc(max_servers*32); //just make things big enough for the bigger test
    int server_output_size = 12 + (msg_len+16+32) + 16 + 32 + (32 + CTX_LEN);
    uint8_t* server_responses = malloc(max_servers*server_output_size);

    uint8_t* msg_recovered = malloc(msg_len);
    uint8_t* context = malloc(CTX_LEN);
    uint8_t* c2 = malloc(32);
    uint8_t* c3 = malloc(CTX_LEN + 32);
    uint8_t* fo = malloc(32);
    uint8_t* r = malloc(16);

    uint8_t* user_key = malloc(16);
    uint8_t* mod_key = malloc(16);

    for(int num_servers = 2; num_servers < max_servers; num_servers++)
    {
        //pick random user and moderator keys
        if(1 != RAND_priv_bytes(user_key, 16))
        {
            printf("couldn't get randomness!\n");
            return 0;
        }
        if(1 != RAND_priv_bytes(mod_key, 16))
        {
            printf("couldn't get randomness!\n");
            return 0;
        }

        //send
        int write_request_vector_len = send(user_key, msg, msg_len, num_servers, &write_request_vector);
        int expected_write_request_vector_len = 12+(msg_len+16+32)+16+32+16*num_servers;
        //expecting plaintext to be msg||r||fo
        //then c1 = iv ||ciphertext||tag, c2 = hmac output
        //then first write request has 16 byte s_1; other write requests are just s_i, with |s_i|=16 bytes

        if(write_request_vector_len != expected_write_request_vector_len)
        {
            printf("write request vector length does not match expectations (%d server case).\n", num_servers);
            printf("write request length: %d, expected %d\n", write_request_vector_len, expected_write_request_vector_len);
            printf("message length: %d\n", msg_len);
            return 0;
        }

        //process
        int ct_share_len = 12 + (msg_len+16+32) + 16 + 32;
        uint8_t* si;
        uint8_t* hi;
        uint8_t* server_out;
        for(int i = 1; i < num_servers; i++)
        {
            si = write_request_vector + ct_share_len + 16*i;
            hi = s_hashes + i*32;
            server_out = server_responses + i*server_output_size;

            if(1 != process(si, ct_share_len, hi, server_out))
            {
                printf("couldn't process (server number: %d, total servers: %d)\n", i, num_servers);
                return 0;
            }
        }
        //moderator needs to process last
        si = write_request_vector + ct_share_len;
        memset(context, 'c', 32);
        server_out = server_responses;
        if(1 != mod_process(num_servers, mod_key, write_request_vector, ct_share_len, si, context, s_hashes, server_out))
        {
            printf("moderator couldn't process (total servers: %d)\n", num_servers);
            return 0;
        }

        //read
        int share_len = ct_share_len + CTX_LEN + 32;
        int recovered_len = read(user_key, num_servers, server_responses, share_len, msg_recovered, r, c2, c3, fo);
        if(recovered_len != msg_len)
        {
            printf("recovered message incorrect length\n");
            printf("expected %d, got %d\n", msg_len, recovered_len);
            return 0;
        }
        if(memcmp(msg, msg_recovered, recovered_len) != 0)
        {
            printf("recovered message incorrect!\n");
            return 0;
        }

        //make a copy of c3 for other tests because verification modifies it
        uint8_t* c3_copy = malloc(CTX_LEN+32);
        memcpy(c3_copy, c3, CTX_LEN+32);

        //verify
        int verifies = verify(mod_key, num_servers, msg_recovered, recovered_len, r, c2, c3, fo);
        if(verifies != 1)
        {
            printf("moderator could not verify!\n");
            return 0;
        }
        if(memcmp(context, c3, CTX_LEN) != 0)
        {
            printf("recovered incorrect context!\n");
            return 0;
        }

        //TODO additional tests where bits are flipped and we expect decryption/verification to fail

        return 1;

    }

    free(write_request_vector);
    free(s_hashes);
    free(server_responses);
    free(msg_recovered);
    free(context);
    free(c2);
    free(c3);
    free(fo);
    free(r);
    free(mod_key);
    free(user_key);
}


int main()
{
    printf("hello!\n");

    int basic_result = basic_crypto_tests();
    int ccAE_result = ccAE_tests();
    int franking_result = shared_franking_tests();

    if(basic_result == 1 && ccAE_result == 1 && franking_result == 1)
    {
        printf("tests passed.\n");
        return 0;
    }
    else
    {
        printf("tests failed.\n");
        return 1;
    }
}
