#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define SERVER_IP "10.75.12.66"
#define SERVER_PORT 12000
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16 // AES block size is 16 bytes

void handle_error(const char *msg) {
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    unsigned char buffer[4096];
    RSA *server_pubkey = NULL;
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char encrypted_aes_key[512];
    unsigned char encrypted_msg[AES_BLOCK_SIZE];
    unsigned char decrypted_msg[AES_BLOCK_SIZE + 1] = {0}; 
    int ret;

    // Initialize OpenSSL algorithms and error strings
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    printf("Creating socket connection to the server\n");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) handle_error("Socket creation failed");

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0)
        handle_error("Invalid address");

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        handle_error("Connection failed");

    printf("Connected to server %s:%d\n", SERVER_IP, SERVER_PORT);

    printf("Receiving and processing the server's public key\n");
    int key_size; 
    if (recv(sockfd, &key_size, sizeof(key_size), 0) != sizeof(key_size))
        handle_error("Failed to read key size");

    printf("Public key size: %d bytes\n", key_size);

    // Receive the server's public key
    if (recv(sockfd, buffer, key_size, 0) != key_size)
        handle_error("Failed to read public key");

    // Convert PEM format to RSA structure
    BIO *keybio = BIO_new_mem_buf(buffer, key_size);
    server_pubkey = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
    BIO_free(keybio);

    if (!server_pubkey) handle_error("Failed to load public key");

    printf("Generating AES key for the client\n");

    if (!RAND_bytes(aes_key, AES_KEY_SIZE))
        handle_error("Failed to generate AES key");

    printf("Generated AES Key: ");
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");

    printf("Encrypting AES key using the server's public key\n");
    
    int rsa_size = RSA_size(server_pubkey);
    ret = RSA_public_encrypt(AES_KEY_SIZE, aes_key, encrypted_aes_key, server_pubkey, RSA_PKCS1_PADDING);

    if (ret == -1) handle_error("Failed to encrypt AES key");

    printf("Encrypted AES key length: %d bytes\n", ret);

    printf("Sending the encrypted AES key to the server\n");

    // Send encrypted AES key size (as int, no byte order conversion)
    if (send(sockfd, &ret, sizeof(int), 0) != sizeof(int))
        handle_error("Failed to send encrypted key size");

    // Send encrypted AES key
    if (send(sockfd, encrypted_aes_key, ret, 0) != ret)
        handle_error("Failed to send encrypted AES key");

    printf("Receiving the encrypted secret message from the server\n");

    // Receive the encrypted secret (fixed size: AES_BLOCK_SIZE bytes)
    ssize_t bytes_read = recv(sockfd, encrypted_msg, AES_BLOCK_SIZE, 0);

    if (bytes_read <= 0) {
        if (bytes_read == 0)
            printf("Connection closed by server while reading encrypted message\n");
        else
            printf("Error reading encrypted message\n");
        close(sockfd);
        return 1;
    }

    printf("Successfully received %zd bytes of encrypted data\n", bytes_read);

    printf("Decrypting the secret message using AES-ECB\n");

    AES_KEY aes_dec_key;
    if (AES_set_decrypt_key(aes_key, 128, &aes_dec_key) < 0)
        handle_error("Failed to set AES decryption key");
    AES_ecb_encrypt(encrypted_msg, decrypted_msg, &aes_dec_key, AES_DECRYPT);

    decrypted_msg[AES_BLOCK_SIZE] = '\0';

    printf("Converting the 16-byte secret to characters\n");

    printf("Decrypted message: %s\n", decrypted_msg);

    FILE *fp = fopen("secret.txt", "w");

    if (!fp) handle_error("Failed to open file for writing");

    fprintf(fp, "%s", decrypted_msg);

    fclose(fp);
    printf("Decrypted message written to secret.txt\n");

    // Clean up
    RSA_free(server_pubkey);
    close(sockfd);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
