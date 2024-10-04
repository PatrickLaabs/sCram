/*
Copyright © 2024 Patrick Laabs patrick.laabs@me.com
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define SALT_LENGTH 16
#define ITERATIONS 4096
#define HASH_LENGTH SHA256_DIGEST_LENGTH

// Generate a random salt
void generate_salt(unsigned char *salt, int length) {
    RAND_bytes(salt, length);
}

// Base64 encode function
char *base64_encode(const unsigned char *input, int length) {
    BIO *b64, *bmem;
    BUF_MEM *bptr;
    char *buff;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    BIO_free_all(b64);
    return buff;
}

// Perform HMAC-SHA256
void hmac_sha256(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *result) {
    HMAC(EVP_sha256(), key, key_len, data, data_len, result, NULL);
}

// Perform the SCRAM-SHA-256 process (password hashing with salt and iteration count)
void scram_sha256(const char *password, const unsigned char *salt, int salt_len, int iterations, unsigned char *output) {
    unsigned char key[HASH_LENGTH];
    unsigned char intermediate[HASH_LENGTH];

    // Combine salt with a counter (1 as per SCRAM spec)
    unsigned char salt1[salt_len + 4];
    memcpy(salt1, salt, salt_len);
    salt1[salt_len] = 0;
    salt1[salt_len + 1] = 0;
    salt1[salt_len + 2] = 0;
    salt1[salt_len + 3] = 1;

    // First iteration of HMAC-SHA-256
    hmac_sha256((unsigned char *)password, strlen(password), salt1, salt_len + 4, key);
    memcpy(intermediate, key, HASH_LENGTH);

    // Perform remaining iterations
    for (int i = 1; i < iterations; i++) {
        hmac_sha256((unsigned char *)password, strlen(password), intermediate, HASH_LENGTH, intermediate);
        for (int j = 0; j < HASH_LENGTH; j++) {
            key[j] ^= intermediate[j];
        }
    }

    memcpy(output, key, HASH_LENGTH);
}

// Derive client key, stored key, and server key
void derive_scram_keys(const unsigned char *salted_password, unsigned char *client_key, unsigned char *server_key) {
    hmac_sha256(salted_password, HASH_LENGTH, (unsigned char *)"Client Key", 10, client_key);
    hmac_sha256(salted_password, HASH_LENGTH, (unsigned char *)"Server Key", 10, server_key);
}

// Main function to encrypt password like PostgreSQL
int main(int arg, char *argv[]) {
    if (arg != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }

    const char *password = argv[1];
    unsigned char salt[SALT_LENGTH];
    unsigned char salted_password[HASH_LENGTH];
    unsigned char client_key[HASH_LENGTH];
    unsigned char stored_key[HASH_LENGTH];
    unsigned char server_key[HASH_LENGTH];

    // Generate random salt
    generate_salt(salt, SALT_LENGTH);

    // Perform SCRAM-SHA-256 hashing with iterations
    scram_sha256(password, salt, SALT_LENGTH, ITERATIONS, salted_password);

    // Derive client key and server key
    derive_scram_keys(salted_password, client_key, server_key);

    // Hash the client key to get the stored key
    SHA256(client_key, HASH_LENGTH, stored_key);

    // Base64 encode salt, stored key, and server key
    char *salt_base64 = base64_encode(salt, SALT_LENGTH);
    char *stored_key_base64 = base64_encode(stored_key, HASH_LENGTH);
    char *server_key_base64 = base64_encode(server_key, HASH_LENGTH);

    // Output in PostgreSQL SCRAM-SHA-256 format
    printf("SCRAM-SHA-256$%d:%s$%s:%s\n", ITERATIONS, salt_base64, stored_key_base64, server_key_base64);

    // Free allocated memory
    free(salt_base64);
    free(stored_key_base64);
    free(server_key_base64);

    return 0;
}
