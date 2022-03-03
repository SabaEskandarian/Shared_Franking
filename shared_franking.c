#include "crypto_tools.h"
#include "shared_franking.h"


//user_key is 16 bytes
//write_request_vector is ct length (which is msg_len + 108) plus prg_output_len (which is 32*num_servers - 16)
//returns length of write_request_vector
int send(uint8_t* user_key, uint8_t* msg, int msg_len, int num_servers, uint8_t** write_request_vector)
{

        //prepare write_request_vector
        int c1_ct_len = 12 + msg_len + 16 + 32; //for iv and ct of m, r, and ccAE hmac key
        int ct_len = c1_ct_len + 16 + 32; //holds c1_ct, c1_tag, c2
        int prg_output_len = (2*num_servers-1)*16;
        int res_len = ct_len + prg_output_len;
        uint8_t* results = malloc(res_len);

        //generate random PRG seed r
        uint8_t* r = malloc(16);
        if(1 != RAND_priv_bytes(r, 16))
        {
            printf("couldn't get randomness!\n");
            return 0;
        }

        //encrypt (m,r) using ccAE. ciphertext is concatenation of all parts of resulting ciphertext

        uint8_t* plaintext = malloc(msg_len+16);
        memcpy(plaintext, msg, msg_len);
        memcpy(plaintext + msg_len, r, 16);

        if(c1_ct_len !=
            ccAEEnc(user_key, plaintext, msg_len+16, results, results + c1_ct_len, results + c1_ct_len + 16))
        {
            printf("error in ccAE encryption; c1_ct_len = %d\n", c1_ct_len);
            return 0;
        }

        //use PRG on r to get r_i for i\in 1...num_servers and s_i for s\in 2...num_servers
        //NOTE: these are interpreted as r_1, s_2,r_2, etc
        if(1 != prg(r, results+ct_len, prg_output_len))
        {
            printf("error in PRG\n");
            return 0;
        }

        //for each s_i, i\in2,...,num_servers, take G(s_i) with output length ct_len and xor into ct
        uint8_t* s_i_prg_output = malloc(ct_len);
        for(int i = 1; i < num_servers; i++)
        {
            int seed_offset = ct_len + 16 + (i-1)*32;
            if(1 != prg(results + seed_offset, s_i_prg_output, ct_len))
            {
                printf("error in PRG\n");
                return 0;
            }
            for(int j = 0; j < ct_len; j++)
            {
                results[j] = results[j] ^ s_i_prg_output[j];
            }
        }

        //results holds the share [c]_1, r_1 followed by (s_i,r_i) for i\in {2,...,num_servers}
        *write_request_vector = results;

        free(r);
        free(plaintext);
        free(s_i_prg_output);

        return res_len;
}

//inputs s,r are 16 bytes each
//output h is 32 bytes
//output server_out is ct_share_len + (\ell + |ctx|) = ct_share_len + (32 + CTX_LEN)
//return 0 on fail, 1 on success
int process(uint8_t* s, uint8_t* r, int ct_share_len, uint8_t* h, uint8_t* server_out)
{
    //expand s via PRG to get the output ct share
    if(1 != prg(s, server_out, ct_share_len))
    {
        printf("error in PRG\n");
        return 0;
    }

    //set h (32 bytes) to be hash of s (16 bytes)
    digest_message(s, 16, h);

    //set u (latter part of server output) to be prg of r
    if(1 != prg(r, server_out+ct_share_len, 32+CTX_LEN))
    {
        printf("error in PRG\n");
        return 0;
    }

    return 1;
}

//input mod_key has length 16
//input r has length 16
//output server_out is ct_share_len + (\ell + |ctx|) = ct_share_len + (32 + CTX_LEN)
int mod_process(int num_servers, uint8_t* mod_key, uint8_t* ct_share, int ct_share_len, uint8_t* r, uint8_t* context, uint8_t* s_hashes, uint8_t* server_out)
{
    //copy ct to server output
    memcpy(server_out, ct_share, ct_share_len);

    //copy context to the appropriate place in the output
    memcpy(server_out + ct_share_len, context, 32);

    //create the tag \sigma and place it in the appropriate place in the server output
    int tag_data_length = 32 + (num_servers-1)*32 + CTX_LEN; //length of ([c_2]_1, s_hashes, ctx)
    uint8_t* tag_data = malloc(tag_data_length);
    memcpy(tag_data, ct_share + ct_share_len - 32, 32); //copy in [c_2]_1
    memcpy(tag_data + 32, s_hashes, (num_servers-1)*32); //copy in s_hashes
    memcpy(tag_data + tag_data_length - CTX_LEN, context, CTX_LEN); //copy in context
    if(1 != hmac_it(mod_key, tag_data, tag_data_length, server_out + ct_share_len + CTX_LEN))
    {
        printf("failed to HMAC\n");
        return 0;
    }

    //generate u, mask on latter part of server output, as prg of r
    uint8_t* mask = malloc(CTX_LEN + 32);
    if(1 != prg(r, mask, CTX_LEN + 32))
    {
        printf("error in PRG\n");
        return 0;
    }

    //xor the mask into (ctx,\sigma)
    for(int i = 0; i < CTX_LEN + 32; i++)
    {
        server_out[ct_share_len + i] = server_out[ct_share_len + i] ^ mask[i];
    }

    free(tag_data);
    free(mask);

    return 1;
}

//returns message length
int read(uint8_t* user_key, int num_servers, uint8_t* shares, int share_len, uint8_t* msg, uint8_t* context, uint8_t* c2, uint8_t* tag, uint8_t* fo, uint8_t* s_vector)
{
    //merge shares
    uint8_t* merged_ct = malloc(share_len);
    //copy in first share
    memcpy(merged_ct, shares, share_len);
    //xor in remaining shares
    for(int i = 1; i < num_servers; i++)
    {
        for(int j = 0; j < share_len; j++)
        {
            merged_ct[j] = merged_ct[j] ^ shares[i*share_len + j];
        }
    }

    int c1_len = share_len - (CTX_LEN + 32) - 32 - 16;
    uint8_t* c1_ct = merged_ct; //c1 is main ciphertext (incl. iv)
    uint8_t* c1_tag = merged_ct + c1_len;
    uint8_t* c2_pointer = merged_ct + c1_len + 16; //c2 is the compactly committing tag
    uint8_t* c3 = merged_ct + c1_len + 16 + 32; //c3 is masked (ctx,\sigma)

    uint8_t* plaintext = malloc(c1_len - 12);//c1 has iv in front of encrypted plaintext

    //decrypt c1,c2 to get m,r,fo
    int pt_len = ccAEDec(user_key, c1_ct, c1_len, c1_tag, c2_pointer, plaintext, fo);
    if(pt_len < c1_len - 12)
    {
        printf("decryption failure\n");
        return 0;
    }
    //copy first part of pt to msg, set second part to be r
    memcpy(msg, plaintext, pt_len - 16);
    uint8_t* r = plaintext + pt_len - 16;

    //use PRG on r to get r_i for i\in 1...num_servers and s_i for s\in 2...num_servers
    //NOTE: these are interpreted as r_1, s_2,r_2, etc
    int prg_output_len = (2*num_servers-1)*16;
    uint8_t* prg_outputs = malloc(prg_output_len);
    if(1 != prg(r, prg_outputs, prg_output_len))
    {
        printf("error in PRG\n");
        return 0;
    }

    int mask_len = CTX_LEN + 32;
    uint8_t* mask = malloc(mask_len);
    uint8_t* ri;
    uint8_t* si;

    for(int i = 0; i < num_servers; i++)
    {
        ri = prg_outputs + i*32;
        //use r_i to generate ith server's mask and xor into c3
        if(1 != prg(ri, mask, mask_len))
        {
            printf("error in PRG\n");
            return 0;
        }
        for(int j = 0; j < mask_len; j++)
        {
            c3[j] = c3[j] ^ mask[j];
        }

        //for i>0, copy s_i into the output s_vector
        if(i > 0)
        {
            si = ri - 16;
            memcpy(s_vector + (i-1)*16, si, 16);
        }
    }

    //copy unmasked (ctx,\sigma) to correct locations
    memcpy(context, c3, CTX_LEN);
    memcpy(tag, c3+CTX_LEN, 32);

    //copy c2_pointer to c2 output
    memcpy(c2, c2_pointer, 32);

    free(merged_ct);
    free(plaintext);
    free(prg_outputs);
    free(mask);

    return pt_len - 16;
}

//1 is accept, 0 is reject
int verify(uint8_t* mod_key, int num_servers, uint8_t* msg, int msg_len, uint8_t* context, uint8_t* c2, uint8_t* tag, uint8_t* fo, uint8_t* s_vector)
{
    int mac_data_len = 32 + num_servers*32 + CTX_LEN;
    uint8_t* mac_data = malloc(mac_data_len); // will hold ([c_2]_1, (H(s_2), ..., H(s_N)), ctx)

    int fail = 0;
    int result = 1;

    //compute [c_2]_1, put it in the beginning of the mac data
    //also compute the hashes of the s_vector values and put them in mac data after [c_2]_1
    memcpy(mac_data, c2, 32);
    int full_ct_len = 12 + msg_len + 16 + 32; //size of (c1, c2) includes iv, msg, c1_tag, c2
    uint8_t* share = malloc(full_ct_len);
    for(int i = 1; i < num_servers; i++)
    {
        if(1 != prg(s_vector + (i-1)*16, share, full_ct_len))
        {
            printf("error in PRG\n");
            return 0;
        }

        for(int j = 0; j < 32; j++)
        {
            mac_data[j] = mac_data[j] ^ share[full_ct_len - 32 + j];
        }

        //set appropriate part of data to (32 bytes) to be hash of s_i (16 bytes)
        digest_message(s_vector + 16*(i-1), 16, mac_data + 32 + 16*(i-1));
    }

    //copy ctx to mac data
    memcpy(mac_data + mac_data_len - CTX_LEN, context, CTX_LEN);

    if(1 != verify_hmac(mod_key, mac_data, mac_data_len, tag))
    {
        fail = 1;
    }

    if(1 != ccAEVerify(msg, msg_len, c2, fo))
    {
        fail = 1;
    }

    if(fail == 1)
    {
        result = 0;
    }

    free(mac_data);
    free(share);

    return result;
}
