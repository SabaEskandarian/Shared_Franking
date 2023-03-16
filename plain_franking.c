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
    printf("hello! These are the plain franking evaluation results.\n");

    int max_msg_len = 1020;
    int msg_len_increments = 20;
    int num_iterations = 1000;//number of times to run each test

    unsigned long times_send[num_iterations];
    unsigned long times_platform[num_iterations];
    unsigned long times_read[num_iterations];
    unsigned long times_verify[num_iterations];

    struct timespec start, finish;

    printf("data taken from %d iterations for each parameter setting. Times are reported in ns.\n", num_iterations);
    printf("msg_len, send_mean, send_stddev, platform_mean, platform_stddev, read_mean, read_stddev, verify_mean, verify_stddev\n");

    for(int msg_len = msg_len_increments; msg_len <= max_msg_len; msg_len += msg_len_increments)
    {
        for(int iteration = 0; iteration < num_iterations; iteration++)
        {
            unsigned char* msg = malloc(msg_len);
            memset(msg, 'a', msg_len);
            uint8_t* c1_ct = malloc(12+msg_len+32);//32 bytes bigger to hold encrypted fo, 12 bytes bigger for iv at beginning
            uint8_t* c1_tag = malloc(16);
            uint8_t* c2 = malloc(32);

            uint8_t* mac_msg = malloc(32 + CTX_LEN);
            uint8_t* ver_mac_msg = malloc(32 + CTX_LEN);
            uint8_t* msg_recovered = malloc(msg_len);
            uint8_t* context = malloc(CTX_LEN);
            uint8_t* sigma = malloc(32);
            uint8_t* fo = malloc(32);

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
            int ct_len = ccAEEnc(user_key, msg, msg_len, c1_ct, c1_tag, c2);
            clock_gettime( CLOCK_REALTIME, &finish );
            times_send[iteration] = ns_difference(finish, start);

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

            //process
            memset(context, 'c', CTX_LEN);

            clock_gettime( CLOCK_REALTIME, &start );
            memcpy(mac_msg, c2, 32);
            memcpy(mac_msg+32, context, CTX_LEN);
            int macSuccess = hmac_it(mod_key, mac_msg, 32 + CTX_LEN, sigma);
            clock_gettime( CLOCK_REALTIME, &finish );
            times_platform[iteration] = ns_difference(finish, start);

            if(1 != macSuccess)
            {
                printf("HMAC computation failed!\n");
                return 0;
            }

            //read
            clock_gettime( CLOCK_REALTIME, &start );
            int pt_len = ccAEDec(user_key, c1_ct, ct_len, c1_tag, c2, msg_recovered, fo);
            clock_gettime( CLOCK_REALTIME, &finish );
            times_read[iteration] = ns_difference(finish, start);

            if(pt_len < 1)
            {
                printf("decryption failure\n");
                printf("ct len: %d\n", ct_len);
                printf("pt len: %d\n", pt_len);
                printf("msg len: %d\n", msg_len);
                printf("iteration: %d\n", iteration);
                return 0;
            }
            if(strncmp(msg, msg_recovered, pt_len) != 0 || msg_len != pt_len)
            {
                printf("decryption incorrect!\n");
                return 0;
            }

            //verify
            clock_gettime( CLOCK_REALTIME, &start );
            int verifySuccess = 0;
            memcpy(ver_mac_msg, c2, 32);
            memcpy(ver_mac_msg+32, context, CTX_LEN);
            int macVerifySuccess = verify_hmac(mod_key, ver_mac_msg, 32+CTX_LEN, sigma);
            int ccAEVerifySuccess = ccAEVerify(msg_recovered, pt_len, c2, fo);
            if(macVerifySuccess == 1 && ccAEVerifySuccess == 1)
            {
                verifySuccess = 1;
            }
            clock_gettime( CLOCK_REALTIME, &finish );
            times_verify[iteration] = ns_difference(finish, start);

            if(1 != verifySuccess)
            {
                printf("verification failure\n");
                return 0;
            }

            free(c1_ct);
            free(c1_tag);
            free(c2);
            free(fo);
            free(mac_msg);
            free(ver_mac_msg);

            free(msg);
            free(msg_recovered);
            free(context);
            free(sigma);
            free(mod_key);
            free(user_key);
        }


        //calculate/output mean and stddev for each function, print them out
        //printf("msg_len, send_mean, send_stddev, pis_mean, pis_stddev, p1_mean, p1_stddev, read_mean, read_stddev, verify_mean, verify_stddev\n");
        printf("%d,", msg_len);
        //printf("send:\n");
        print_stats(times_send, num_iterations);
        //printf("platform:\n");
        print_stats(times_platform, num_iterations);
        //printf("read:\n");
        print_stats(times_read, num_iterations);
        //printf("verify:\n");
        print_stats(times_verify, num_iterations);
        printf("\n");

    }

    printf("\ndone.\n");
    return 0;
}
