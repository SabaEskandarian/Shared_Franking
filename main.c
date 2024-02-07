#include "crypto_tools.h"
#include "shared_franking.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/rand.h>
#include <time.h>
#include <math.h>

unsigned long ns_difference(struct timespec finish, struct timespec start)
{
    unsigned long NS_PER_SECOND = 1000000000;

    unsigned long nsec_diff = finish.tv_nsec - start.tv_nsec;
    unsigned long sec_diff  = finish.tv_sec - start.tv_sec;

    return nsec_diff + sec_diff * NS_PER_SECOND;
}

void print_stats(unsigned long times[], int times_len)
{
    unsigned long sum = 0;
    for(int i = 0; i < times_len; i++)
    {
        sum += times[i];
    }
    double mean = sum / times_len;

    double var = 0;
    for(int i = 0; i < times_len; i++)
    {
        var += (times[i] - mean)*(times[i] - mean);
    }
    var /= times_len;

    double stddev = sqrt(var);

    printf("%f,%f,", mean, stddev);

    //printf("mean (ns): %f\n", mean);
    //printf("standard deviation: %f\n", stddev);

    return;
}

int main()
{
    printf("hello! These are the shared franking evaluation results.\n");


    //test shared franking
    int max_servers = 10;
    int max_msg_len = 1020;
    int msg_len_increments = 20;
    int num_iterations = 1000;//number of times to run each test

    unsigned long times_send[num_iterations];
    unsigned long times_pis[num_iterations];
    unsigned long times_p1[num_iterations];
    unsigned long times_read[num_iterations];
    unsigned long times_verify[num_iterations];

    struct timespec start, finish;

    printf("data taken from %d iterations for each parameter setting. Times are reported in ns.\n", num_iterations);
    printf("msg_len, num_servers, send_mean, send_stddev, pis_mean, pis_stddev, p1_mean, p1_stddev, read_mean, read_stddev, verify_mean, verify_stddev\n");

    for(int msg_len = msg_len_increments; msg_len <= max_msg_len; msg_len += msg_len_increments)
    {



        for(int num_servers = 2; num_servers <= max_servers; num_servers++)
        {

            //printf("num_servers: %d, msg_len: %d\n", num_servers, msg_len);

            for(int iteration = 0; iteration < num_iterations; iteration++)
            {
                unsigned char* msg = malloc(msg_len);
                memset(msg, 'a', msg_len);
                uint8_t* write_request_vector;
                uint8_t* s_hashes = malloc((num_servers-1)*32);
                int server_output_size = 12 + (msg_len+16+32) + 16 + 32 + (32 + CTX_LEN + 32);
                uint8_t* server_responses = malloc(num_servers*server_output_size);

                uint8_t* msg_recovered = malloc(msg_len);
                uint8_t* context = malloc(CTX_LEN);
                uint8_t* c2_1 = malloc(32);
                uint8_t* ctx = malloc(CTX_LEN);
                uint8_t* sigma = malloc(32);
                uint8_t* fo = malloc(32);
                uint8_t* r = malloc(16);

                uint8_t* user_key = malloc(16);
                uint8_t* mod_key = malloc(32);

                int flag = 0;

                //pick random user and moderator keys
                if(1 != RAND_priv_bytes(user_key, 16))
                {
                    printf("couldn't get randomness!\n");
                    return 1;
                }
                if(1 != RAND_priv_bytes(mod_key, 32))
                {
                    printf("couldn't get randomness!\n");
                    return 1;
                }

                //send
                clock_gettime( CLOCK_REALTIME, &start );
                int write_request_vector_len = send(user_key, msg, msg_len, num_servers, &write_request_vector);
                clock_gettime( CLOCK_REALTIME, &finish );
                times_send[iteration] = ns_difference(finish, start);

                int expected_write_request_vector_len = 12+(msg_len+16+32)+16+32+16*num_servers;
                //expecting plaintext to be msg||r||fo
                //then c1 = iv ||ciphertext||tag, c2 = hmac output
                //then first write request has 16 byte s_1; other write requests are just s_i, with |s_i|=16 bytes

                if(write_request_vector_len != expected_write_request_vector_len)
                {
                    printf("write request vector length does not match expectations (%d server case).\n", num_servers);
                    printf("write request length: %d, expected %d\n", write_request_vector_len, expected_write_request_vector_len);
                    printf("message length: %d\n", msg_len);
                    return 1;
                }

                //process
                int ct_share_len = 12 + (msg_len+16+32) + 16 + 32;
                uint8_t* si;
                uint8_t* hi;
                uint8_t* server_out;
                unsigned long process_sum = 0;
                for(int i = 1; i < num_servers; i++)
                {
                    si = write_request_vector + ct_share_len + 16*i;
                    hi = s_hashes + (i-1)*32;
                    server_out = server_responses + i*server_output_size;

                    clock_gettime( CLOCK_REALTIME, &start );
                    flag = process(si, ct_share_len, hi, server_out);
                    clock_gettime( CLOCK_REALTIME, &finish );
                    process_sum += ns_difference(finish, start);

                    if(1 != flag)
                    {
                        printf("couldn't process (server number: %d, total servers: %d)\n", i, num_servers);
                        return 1;
                    }
                }
                times_pis[iteration] = process_sum/(num_servers-1);

                //moderator needs to process last
                si = write_request_vector + ct_share_len;
                memset(context, 'c', 32);
                server_out = server_responses;

                clock_gettime( CLOCK_REALTIME, &start );
                flag = mod_process(num_servers, mod_key, write_request_vector, ct_share_len, si, context, s_hashes, server_out);
                clock_gettime( CLOCK_REALTIME, &finish );
                times_p1[iteration] = ns_difference(finish, start);

                if(1 != flag)
                {
                    printf("moderator couldn't process (total servers: %d)\n", num_servers);
                    return 1;
                }

                //read
                int share_len = ct_share_len + CTX_LEN + 32 + 32;

                clock_gettime( CLOCK_REALTIME, &start );
                int recovered_len = read(user_key, num_servers, server_responses, share_len, msg_recovered, r, c2_1, ctx, sigma, fo);
                clock_gettime( CLOCK_REALTIME, &finish );
                times_read[iteration] = ns_difference(finish, start);

                if(recovered_len != msg_len)
                {
                    printf("recovered message incorrect length\n");
                    printf("expected %d, got %d\n", msg_len, recovered_len);
                    return 1;
                }
                if(memcmp(msg, msg_recovered, recovered_len) != 0)
                {
                    printf("recovered message incorrect!\n");
                    return 1;
                }

                //verify
                clock_gettime( CLOCK_REALTIME, &start );
                int verifies = verify(mod_key, num_servers, msg_recovered, recovered_len, r, c2_1, ctx, sigma, fo);
                clock_gettime( CLOCK_REALTIME, &finish );
                times_verify[iteration] = ns_difference(finish, start);

                if(verifies != 1)
                {
                    printf("moderator could not verify!\n");
                    return 1;
                }
                if(memcmp(context, ctx, CTX_LEN) != 0)
                {
                    printf("recovered incorrect context!\n");
                    return 1;
                }

                free(msg);
                free(write_request_vector);
                free(s_hashes);
                free(server_responses);
                free(msg_recovered);
                free(context);
                free(c2_1);
                free(ctx);
                free(sigma);
                free(fo);
                free(r);
                free(mod_key);
                free(user_key);

            }


            //calculate/output mean and stddev for each function, print them out
            //printf("msg_len, num_servers, send_mean, send_stddev, pis_mean, pis_stddev, p1_mean, p1_stddev, read_mean, read_stddev, verify_mean, verify_stddev\n");
            printf("%d,%d,", msg_len, num_servers);
            //printf("send:\n");
            print_stats(times_send, num_iterations);
            //printf("pis:\n");
            print_stats(times_pis, num_iterations);
            //printf("p1:\n");
            print_stats(times_p1, num_iterations);
            //printf("read:\n");
            print_stats(times_read, num_iterations);
            //printf("verify:\n");
            print_stats(times_verify, num_iterations);
            printf("\n");

        }
    }

    printf("\ndone.\n");
    return 0;
}
