/*
Copyright © 2024 Patrick Laabs patrick.laabs@me.com
*/

/*
 * scram_sha256.c
 * 
 * This file contains functions to perform SCRAM-SHA-256 password hashing and key derivation.
 * It includes functions to generate a random salt, perform the SCRAM-SHA-256 process,
 * and derive client and server keys.
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

/*
 * Generate a random salt.
 * 
 * Parameters:
 *   salt - Pointer to the buffer where the generated salt will be stored.
 *   length - Length of the salt to be generated.
 * 
 * Returns:
 *   0 on success, 1 on failure.
 */
int generate_salt(unsigned char *salt, int length) {
    if (RAND_bytes(salt, length) != 1) {
        fprintf(stderr, "Error generating random bytes for salt\n");
        return 1;
    }
    return 0;
}

/*
 * Encode data in base64 format.
 * 
 * Parameters:
 *   input - Pointer to the data to be encoded.
 *   length - Length of the data to be encoded.
 * 
 * Returns:
 *   A pointer to the base64 encoded string. The caller is responsible for freeing the allocated memory.
 *   Returns NULL on failure.
 */
char *base64_encode(const unsigned char *input, int length) {
    BIO *b64, *bmem;
    BUF_MEM *bptr;
    char *buff;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    buff = (char *)malloc(bptr->length + 1);
    if (buff == NULL) {
        fprintf(stderr, "Error allocating memory for base64 encoding\n");
        BIO_free_all(b64);
    BIO_free_all(b64);
    }
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    BIO_free_all(b64);
    return buff;
}

/*
 * Compute HMAC-SHA-256.
 * 
 * Parameters:
 *   key - Pointer to the key.
 *   key_len - Length of the key.
 *   data - Pointer to the data.
 *   data_len - Length of the data.
 *   result - Pointer to the buffer where the result will be stored.
 * 
 * Returns:
 *   0 on success, 1 on failure.
 */
int hmac_sha256(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *result) {
    unsigned int len = HASH_LENGTH;
    if (HMAC(EVP_sha256(), key, key_len, data, data_len, result, &len) == NULL) {
        fprintf(stderr, "Error performing HMAC-SHA-256\n");
        return 1;
    }
    return 0;
}

/*
 * Perform the SCRAM-SHA-256 process (password hashing with salt and iteration count).
 * 
 * Parameters:
 *   password - Pointer to the password.
 *   salt - Pointer to the salt.
 *   salt_len - Length of the salt.
 *   iterations - Number of iterations.
 *   output - Pointer to the buffer where the output will be stored.
 * 
 * Returns:
 *   0 on success, 1 on failure.
 */
int scram_sha256(const char *password, const unsigned char *salt, int salt_len, int iterations, unsigned char *output) {
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
    if (hmac_sha256((unsigned char *)password, strlen(password), salt1, salt_len + 4, key) != 0) {
        return 1;
    }
    memcpy(intermediate, key, HASH_LENGTH);

    // Perform remaining iterations
    for (int i = 1; i < iterations; i++) {
        if (hmac_sha256((unsigned char *)password, strlen(password), intermediate, HASH_LENGTH, intermediate) != 0) {
            return 1;
        }
        for (int j = 0; j < HASH_LENGTH; j++) {
            key[j] ^= intermediate[j];
        }
    }

    memcpy(output, key, HASH_LENGTH);
    return 0;
}

/*
 * Derive client key, stored key, and server key.
 * 
 * Parameters:
 *   salted_password - Pointer to the salted password.
 *   client_key - Pointer to the buffer where the client key will be stored.
 *   server_key - Pointer to the buffer where the server key will be stored.
 * 
 * Returns:
 *   0 on success, 1 on failure.
 */
int derive_scram_keys(const unsigned char *salted_password, unsigned char *client_key, unsigned char *server_key) {
    if (hmac_sha256(salted_password, HASH_LENGTH, (unsigned char *)"Client Key", 10, client_key) != 0) {
        return 1;
    }
    if (hmac_sha256(salted_password, HASH_LENGTH, (unsigned char *)"Server Key", 10, server_key) != 0) {
        return 1;
    }
    return 0;
}

/*
 * Main function.
 * 
 * Parameters:
 *   argc - Argument count.
 *   argv - Argument vector.
 * 
 * Returns:
 *   0 on success, 1 on failure.
 */
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
    if (generate_salt(salt, SALT_LENGTH) != 0) {
        fprintf(stderr, "Error generating salt\n");
        return 1;
    }

    // Perform SCRAM-SHA-256 hashing with iterations
    if (scram_sha256(password, salt, SALT_LENGTH, ITERATIONS, salted_password) != 0) {
        fprintf(stderr, "Error performing SCRAM-SHA-256 hashing\n");
        return 1;
    }

    // Derive client key and server key
    if (derive_scram_keys(salted_password, client_key, server_key) != 0) {
        fprintf(stderr, "Error deriving SCRAM keys\n");
        return 1;
    }

    // Hash the client key to get the stored key
    if (SHA256(client_key, HASH_LENGTH, stored_key) == NULL) {
        fprintf(stderr, "Error hashing client key\n");
        return 1;
    }

    // Base64 encode salt, stored key, and server key
    char *salt_base64 = base64_encode(salt, SALT_LENGTH);
    char *stored_key_base64 = base64_encode(stored_key, HASH_LENGTH);
    char *server_key_base64 = base64_encode(server_key, HASH_LENGTH);

    if (!salt_base64 || !stored_key_base64 || !server_key_base64) {
        fprintf(stderr, "Error encoding to base64\n");
        free(salt_base64);
        free(stored_key_base64);
        free(server_key_base64);
        return 1;
    }

    // Output in PostgreSQL SCRAM-SHA-256 format
    printf("SCRAM-SHA-256$%d:%s$%s:%s\n", ITERATIONS, salt_base64, stored_key_base64, server_key_base64);

    // Free allocated memory
    free(salt_base64);
    free(stored_key_base64);
    free(server_key_base64);

    // Securely erase sensitive data
    memset(salted_password, 0, HASH_LENGTH);
    memset(client_key, 0, HASH_LENGTH);
    memset(stored_key, 0, HASH_LENGTH);
    memset(server_key, 0, HASH_LENGTH);

    return 0;
}
