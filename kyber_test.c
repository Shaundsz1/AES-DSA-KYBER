#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/aes.h>
#include "api.h"

#define SERVER_ADDRESS "10.75.12.66"
#define SERVER_PORT 13000
#define AES_KEYSIZE 128
#define BUFFER_CAPACITY 2048
// Error Handling Function
void log_error_and_exit(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}
int connect_to_server(const char *server_ip, int port) {
    int sockfd;
    struct sockaddr_in server_address;
    
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log_error_and_exit("Socket creation failed");
    }
    
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    
    // Converting IP address to binary form and check for errors
    if (inet_pton(AF_INET, server_ip, &server_address.sin_addr) <= 0) {
        log_error_and_exit("Invalid server address");
    }
    
    // connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        log_error_and_exit("Connection failed");
    }

    printf("Connected to server %s on port %d\n", server_ip, port);
    return sockfd;
}

void kyber_key_exchange(int sockfd, unsigned char *shared_secret) {
    unsigned char public_key[PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char secret_key[PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char server_ciphertext[PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES];

    // Generate Kyber key pair
    if (PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(public_key, secret_key) != 0) {
        log_error_and_exit("Kyber key pair generation failed");
    }

    // Send public key size to the server
    int key_size = PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES;
    if (send(sockfd, &key_size, sizeof(int), 0) != sizeof(int)) {
        log_error_and_exit("Failed to send key size");
    }

    // Send public key to the server
    if (send(sockfd, public_key, key_size, 0) != key_size) {
        log_error_and_exit("Failed to send public key");
    }
    printf("Sent Kyber public key to server.\n");
    // Receive size of server's ciphertext
    int ciphertext_size;
    if (recv(sockfd, &ciphertext_size, sizeof(int), 0) != sizeof(int)) {
        log_error_and_exit("Failed to receive ciphertext size");
    }
    // Receive server's ciphertext
    if (recv(sockfd, server_ciphertext, ciphertext_size, 0) != ciphertext_size) {
        log_error_and_exit("Failed to receive server ciphertext");
    }

    printf("Received server's ciphertext.\n");
    // Decapsulate to get the shared secret
    if (PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(shared_secret, server_ciphertext, secret_key) != 0) {
        log_error_and_exit("Decapsulation failed");
    }

    printf("Shared secret successfully derived.\n");
}
// Function to handle AES decryption
void aes_decrypt_message(int sockfd, unsigned char *shared_secret) {
    AES_KEY aes_key;
    unsigned char encrypted_message[AES_BLOCK_SIZE];
    unsigned char decrypted_message[AES_BLOCK_SIZE + 1]; 

    // Receive encrypted secret message
    if (recv(sockfd, encrypted_message, AES_BLOCK_SIZE, 0) != AES_BLOCK_SIZE) {
        log_error_and_exit("Failed to receive encrypted message");
    }
    printf("Encrypted message received from server.\n");
    // Set AES decryption key
    if (AES_set_decrypt_key(shared_secret, AES_KEYSIZE, &aes_key) < 0) {
        log_error_and_exit("AES key setting failed");
    }

    // Decrypt the message
    AES_decrypt(encrypted_message, decrypted_message, &aes_key);
    decrypted_message[AES_BLOCK_SIZE] = '\0';  

    if (isprint(decrypted_message[0])) { 
        printf("Decrypted message (ASCII): %s\n", decrypted_message);
    } else {
        printf("Decrypted message contains non-ASCII characters.\n");
    }
    // Write the decrypted message to a file
    FILE *file = fopen("decrypted_secret.txt", "w");
    if (file == NULL) {
        log_error_and_exit("Error opening output file");
    }
    fprintf(file, "%s", decrypted_message);
    fclose(file);

    printf("Decrypted message written to 'decrypted_secret.txt'.\n");
}

int main() {

    int sockfd = connect_to_server(SERVER_ADDRESS, SERVER_PORT);
    // Perform Kyber key exchange and ciphertext handling
    unsigned char shared_secret[PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES]; 
    kyber_key_exchange(sockfd, shared_secret);

    // Decrypt the secret message using AES
    aes_decrypt_message(sockfd, shared_secret);
    close(sockfd);

    return 0;
}
