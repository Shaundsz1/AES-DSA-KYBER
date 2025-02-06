#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NUM_SAMPLES 1000000
#define RSA_KEY_SIZE 3072  
#define PLAINTEXT_SIZE 16   
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
    unsigned char plaintext[PLAINTEXT_SIZE] = "1234567890abcdef"; // 16 bytes of data
    unsigned char encrypted[512];  
    // Generate RSA key
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    if (RSA_generate_key_ex(rsa, RSA_KEY_SIZE, bne, NULL) != 1) {
        fprintf(stderr, "RSA key generation failed.\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        BN_free(bne);
        return 1;
    }

    // Open file to save the timing data
    FILE *fp = fopen("rsa.txt", "w");
    if (fp == NULL) {
        perror("Failed to open file");
        RSA_free(rsa);
        BN_free(bne);
        return 1;
    }
    for (int i = 0; i < NUM_SAMPLES; i++) {
        struct timespec start = timer_start();
        int len = RSA_public_encrypt(PLAINTEXT_SIZE, plaintext, encrypted, rsa, RSA_PKCS1_PADDING);
        if (len < 0) {
            ERR_print_errors_fp(stderr);
            continue; // Skip this iteration if encryption failed
        }
        long duration = timer_stop(start);
        fprintf(fp, "%ld\n", duration);
    }

    fclose(fp);
    RSA_free(rsa);
    BN_free(bne);
    return 0;
}
