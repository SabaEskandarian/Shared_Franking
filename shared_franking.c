#include "crypto_tools.h"
#include "shared_franking.h"


//user_key is 16 bytes
//write_request_vector is ct length (which is msg_len + 96) plus prg_output_len (which is 32*num_servers - 16)
//returns length of write_request_vector
int send(uint8_t* user_key, uint8_t* msg, int msg_len, int num_servers, uint8_t** write_request_vector)
{

        //prepare write_request_vector
        int c1_ct_len = msg_len + 16 + 32; //for ct of m, r, and ccAE hmac key
        int ct_len = c1_ct_len + 16 + 32; //holds c1_ct, c1_tag, c2
        int prg_output_len = (2*num_servers-1)*16;
        int res_len = ct_len + prg_output_len
        uint8_t* results = malloc(res_len);

        //generate random PRG seed r
        uint8_t* r = malloc(16);
        if(1 != RAND_priv_bytes(r, 16))
        {
            printf("couldn't get randomness!\n");
            return 0;
        }

        //encrypt (m,r) using ccAE. ciphertext is concatenation of all parts of resulting ciphertext
        //generate random 12 byte IV
        uint8_t* iv = malloc(12);
        if(1 != RAND_priv_bytes(iv, 12))
        {
            printf("couldn't get randomness!\n");
            return 0;
        }

        uint8_t* plaintext = malloc(msg_len+16);
        memcpy(plaintext, msg, msg_len);
        memcpy(plaintext + msg_len, r, 16);

        if(c1_ct_len !=
            ccAEEnc(user_key, plaintext, msg_len+16, iv, results, results + c1_ct_len, results + c1_ct_len + 16))
        {
            printf("error in ccAE encryption; c1_ct_len = %d\n", c1_ct_len);
            return 0;
        }

        //use PRG on r to get r_i for i\in 1...num_servers and s_i for s\in 2...num_servers
        if(1 != prg(r, results+ct_len, prg_output_len))
        {
            printf("error in PRG\n");
            return 0;
        }

        //for each s_i, i\in2,...,num_servers, take G(s_i) with output length ct_len and xor into ct
        uint8_t* s_i_prg_output = malloc(ct_len);
        for(i = 1; i < num_servers; i++)
        {
            int seed_offset = ct_len + 16 + (i-1)*32;
            if(1 != prg(results + seed_offset, s_i_prg_output, ct_len))
            {
                printf("error in PRG\n");
                return 0;
            }
            for(j = 0; j < ct_len; j++)
            {
                results[j] = results[j] ^ s_i_prg_output[j];
            }
        }

        //results holds the share [c]_1, r_1 followed by (s_i,r_i) for i\in {2,...,num_servers}
        *write_request_vector = results;

        free(r);
        free(iv);
        free(plaintext);
        free(s_i_prg_output);

        return res_len;
}

//inputs s,r are 16 bytes each
//output h is 32 bytes
//output server_out is ct_share_len + (\ell + |ctx|) = ct_share_len + (32 + CTX_LEN)
//TODO return 0 on fail, 1 on success
void process(uint8_t* s, uint8_t* r, int ct_share_len, uint8_t* h, uint8_t* server_out)
{
    //expand s via PRG to get the output ct share
    if(1 != prg(s, server_out, ct_share_len))
    {
        printf("error in PRG\n");
        return 0;
    }

    //TODO set h to be hash of s


    //set u (latter part of server output) to be prg of r
    if(1 != prg(r, server_out+ct_share_len, 32+CTX_LEN))
    {
        printf("error in PRG\n");
        return 0;
    }


}

//input mod_key has length 16
//input r has length 16
//output server_out is ct_share_len + (\ell + |ctx|) = ct_share_len + (32 + CTX_LEN)
void modProcess(int num_servers, uint8_t* mod_key, uint8_t* ct_share, int ct_share_len, uint8_t* r, uint8_t* server_out)
{

}

void read(uint8_t* user_key, int num_servers, int share_len, int context_len, int msg_len, uint8_t* msg, uint8_t* context, uint8_t* c2, uint8_t* tag, uint8_t* fo, uint8_t* s_vector)
{

}

void verify(uint8_t* mod_key, int num_servers, uint8_t* msg, int msg_len, uint8_t* context, int context_len, uint8_t* c2, uint8_t* tag, uint8_t* fo, uint8_t* s_vector)
{

}
