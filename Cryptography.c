//The provided C code demonstrates a basic cryptographic scenario using OpenSSL, incorporating Diffie-Hellman key exchange, SHA-256 hashing, and AES encryption/decryption. Here's a summary of the code's functionality:
//Initialization:
//Includes necessary header files and defines constants such as key sizes, IV size, and maximum message size.
//Error Handling Function:
//Defines a function (handleErrors) to print error messages and exit the program.
//Hashing Function:
//Defines a function (hash) to compute the SHA-256 hash of input data.
//Diffie-Hellman Key Exchange:
//Defines a function (performDHKeyExchange) to generate a Diffie-Hellman key pair, perform key exchange, and generate a shared secret.
//AES Encryption and Decryption Functions:
//Defines functions (encrypt and decrypt) for AES encryption and decryption, respectively. Also used CBC.
//Encryption and Decryption Process:
//Defines a function (performEncryptionDecryption) to generate a random Initialization Vector (IV), encrypt a plaintext message using AES, print the ciphertext, decrypt the ciphertext, and print the decrypted plaintext.
//Main Function:
//Initializes a Diffie-Hellman key exchange, computes a shared secret, hashes the secret using SHA-256, prints the hashed shared secret, performs encryption and decryption using the hashed secret, and cleans up allocated resources.
//The code demonstrates secure communication by establishing a shared secret between two parties using Diffie-Hellman, hashing the secret, and using the hashed secret for secure AES encryption and decryption.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/sha.h>

#define KEY_SIZE 16
#define IV_SIZE 16  // Initialization Vector size
#define MAX_MESSAGE_SIZE 64

void handleErrors(const char *err_msg) {
    fprintf(stderr, "Error: %s\n", err_msg);
    exit(EXIT_FAILURE);
}

void hash(const unsigned char *data, int len, unsigned char *digest) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();

    if (!(mdctx = EVP_MD_CTX_new())) {
        handleErrors("EVP_MD_CTX_new");
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        handleErrors("EVP_DigestInit_ex");
    }

    if (1 != EVP_DigestUpdate(mdctx, data, len)) {
        handleErrors("EVP_DigestUpdate");
    }

    unsigned int digestLen;
    if (1 != EVP_DigestFinal_ex(mdctx, digest, &digestLen)) {
        handleErrors("EVP_DigestFinal_ex");
    }

    EVP_MD_CTX_free(mdctx);
}

void hashMessage(const char *message, unsigned char *digest) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();

    if (!(mdctx = EVP_MD_CTX_new())) {
        handleErrors("EVP_MD_CTX_new");
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        handleErrors("EVP_DigestInit_ex");
    }

    if (1 != EVP_DigestUpdate(mdctx, message, strlen(message))) {
        handleErrors("EVP_DigestUpdate");
    }

    unsigned int digestLen;
    if (1 != EVP_DigestFinal_ex(mdctx, digest, &digestLen)) {
        handleErrors("EVP_DigestFinal_ex");
    }

    EVP_MD_CTX_free(mdctx);
}

int performDHKeyExchange(DH **privkey, BIGNUM **pubkey) {
    int codes;

    *privkey = DH_new();
    if (*privkey == NULL)
        handleErrors("DH_new");

    if (1 != DH_generate_parameters_ex(*privkey, 2048, DH_GENERATOR_2, NULL))
        handleErrors("DH_generate_parameters_ex");

    if (1 != DH_check(*privkey, &codes))
        handleErrors("DH_check");

    if (codes != 0) {
        printf("DH_check failed\n");
        abort();
    }

    if (1 != DH_generate_key(*privkey))
        handleErrors("DH_generate_key");

    // Generate a random public key
    *pubkey = BN_new();
    if (*pubkey == NULL)
        handleErrors("BN_new");

    if (1 != BN_rand_range(*pubkey, DH_get0_p(*privkey)))
        handleErrors("BN_rand_range");

    return DH_size(*privkey);
}

int encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("EVP_CIPHER_CTX_new");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors("EVP_EncryptInit_ex");

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors("EVP_EncryptUpdate");

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors("EVP_EncryptFinal_ex");

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("EVP_CIPHER_CTX_new");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors("EVP_DecryptInit_ex");

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors("EVP_DecryptUpdate");

    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors("EVP_DecryptFinal_ex");

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void shareIV(const unsigned char *iv, int iv_size, FILE *outputStream) {
    fprintf(outputStream, "Shared Initialization Vector (IV): ");
    for (int i = 0; i < iv_size; i++)
        fprintf(outputStream, "%02x ", iv[i]);
    fprintf(outputStream, "\n");
}

void performEncryptionDecryption(const unsigned char *key, const char *plaintext) {
    unsigned char cipher[MAX_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char decrypted[MAX_MESSAGE_SIZE];

    // Generate a random IV
    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        handleErrors("RAND_bytes");
    }

    // Share Initialization Vector (IV)
    shareIV(iv, IV_SIZE, stdout);

    int plen = strlen(plaintext);
    int clen = encrypt((const unsigned char *)plaintext, plen, key, iv, cipher);

    printf("Cipher: ");
    for (int i = 0; i < clen; i++)
        printf("%02x ", cipher[i]);
    printf("\n");

    int declen = decrypt(cipher, clen, key, iv, decrypted);

    printf("Decrypted Text: ");
    for (int i = 0; i < declen; i++)
        printf("%c", (const char)decrypted[i]);
    printf("\n");

    // Print Hashed Shared Secret
    unsigned char hashedSecret[SHA256_DIGEST_LENGTH];
    hash(key, KEY_SIZE, hashedSecret);

    printf("Hashed shared secret:\n");
    BIO_dump_fp(stdout, hashedSecret, SHA256_DIGEST_LENGTH);
}

int main() {
    DH *privkey;
    BIGNUM *pubkey;
    int secret_size;

    const char *initialMessage = "This is a secret.";
    unsigned char initialMessageHash[SHA256_DIGEST_LENGTH];
    hashMessage(initialMessage, initialMessageHash);

    printf("Hash of the initial message:\n");
    BIO_dump_fp(stdout, initialMessageHash, SHA256_DIGEST_LENGTH);

    secret_size = performDHKeyExchange(&privkey, &pubkey);

    unsigned char *secret = OPENSSL_malloc(sizeof(unsigned char) * secret_size);
    if (secret == NULL)
        handleErrors("OPENSSL_malloc");

    if (0 > DH_compute_key(secret, pubkey, privkey))
        handleErrors("DH_compute_key");

    unsigned char hashedSecret[SHA256_DIGEST_LENGTH];
    hash(secret, secret_size, hashedSecret);

    printf("Hashed shared secret:\n");
    BIO_dump_fp(stdout, hashedSecret, SHA256_DIGEST_LENGTH);

    performEncryptionDecryption(hashedSecret, initialMessage);

    // Clean up
    OPENSSL_free(secret);
    BN_free(pubkey);
    DH_free(privkey);

    return 0;
}