#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NUM_SAMPLES 1000000
struct timespec timer_start() {
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    return start;
}
long timer_stop(struct timespec start) {
    struct timespec stop;
    clock_gettime(CLOCK_MONOTONIC, &stop);
    return stop.tv_sec * 1000000000 + stop.tv_nsec - (start.tv_sec * 1000000000 + start.tv_nsec);
}
int main() {
    unsigned char key[AES_BLOCK_SIZE];
    unsigned char in[AES_BLOCK_SIZE];
    unsigned char out[AES_BLOCK_SIZE];
    AES_KEY enc_key;

    RAND_bytes(key, AES_BLOCK_SIZE);
    RAND_bytes(in, AES_BLOCK_SIZE);
    AES_set_encrypt_key(key, 128, &enc_key);

    FILE *fp = fopen("aes.txt", "w");
    if (fp == NULL) {
        perror("Failed to open file");
        return 1;
    }

    for (int i = 0; i < NUM_SAMPLES; i++) {
        struct timespec start = timer_start();
        AES_encrypt(in, out, &enc_key);
        long duration = timer_stop(start);
        fprintf(fp, "%ld\n", duration);
    }
    fclose(fp);

    return 0;
}
