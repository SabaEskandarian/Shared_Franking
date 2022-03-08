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

    printf("mean (ns): %f\n", mean);
    printf("standard deviation: %f\n", stddev);

    return;
}

int main()
{
    printf("hello!\n");


    //test shared franking
    int max_servers = 10;
    int max_msg_len = 1000;
    int msg_len_increments = 20;
    int num_iterations = 1000;//number of times to run each test

    unsigned long times_send[num_iterations];
    unsigned long times_pis[num_iterations];
    unsigned long times_p1[num_iterations];
    unsigned long times_read[num_iterations];
    unsigned long times_verify[num_iterations];

    struct timespec start, finish;

    printf("data taken from %d iterations for each parameter setting\n", num_iterations);

    for(int msg_len = msg_len_increments; msg_len <= max_msg_len; msg_len += msg_len_increments)
    {

        for(int num_servers = 2; num_servers <= max_servers; num_servers++)
        {

            printf("num_servers: %d, msg_len: %d\n", num_servers, msg_len);

            for(int iteration = 0; iteration < num_iterations; iteration++)
            {

                //TODO actual code goes here later

                clock_gettime( CLOCK_REALTIME, &start );
                //TODO times segment goes in a place like this
                clock_gettime( CLOCK_REALTIME, &finish );
                times_send[iteration] = ns_difference(finish, start);

            }


            //calculate/output mean and stddev for each function, print them out
            printf("send:\n");
            print_stats(times_send, num_iterations);
            printf("pis:\n");
            print_stats(times_pis, num_iterations);
            printf("p1:\n");
            print_stats(times_p1, num_iterations);
            printf("read:\n");
            print_stats(times_read, num_iterations);
            printf("verify:\n");
            print_stats(times_verify, num_iterations);
            printf("\n");
        }


    }

    printf("\ndone.\n");
    return 0;
}
