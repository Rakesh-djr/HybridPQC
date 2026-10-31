#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s", label);

    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", data[i]);
    }

    printf("\n");
}

int main(void)
{
    printf("========================================\n");
    printf("       X25519 TEST PROGRAM\n");
    printf("========================================\n\n");

    EVP_PKEY *alice_key = NULL;
    EVP_PKEY *bob_key = NULL;

    EVP_PKEY_CTX *alice_ctx = NULL;
    EVP_PKEY_CTX *bob_ctx = NULL;

    EVP_PKEY_CTX *alice_derive_ctx = NULL;
    EVP_PKEY_CTX *bob_derive_ctx = NULL;

    unsigned char *alice_public = NULL;
    unsigned char *bob_public = NULL;

    size_t alice_public_len = 0;
    size_t bob_public_len = 0;

    unsigned char alice_shared_secret[32];
    unsigned char bob_shared_secret[32];

    size_t alice_secret_len = sizeof(alice_shared_secret);
    size_t bob_secret_len = sizeof(bob_shared_secret);

    /*
     * --------------------------------------------------
     * 1. Generate Alice's X25519 key pair
     * --------------------------------------------------
     */

    printf("[1] Generating Alice's X25519 key pair...\n");

    alice_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (alice_ctx == NULL)
    {
        printf("ERROR: Could not create Alice key context.\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(alice_ctx) <= 0)
    {
        printf("ERROR: Alice key generation initialization failed.\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen(alice_ctx, &alice_key) <= 0)
    {
        printf("ERROR: Alice key generation failed.\n");
        goto cleanup;
    }

    printf("    Alice key pair generated successfully.\n\n");

    /*
     * --------------------------------------------------
     * 2. Generate Bob's X25519 key pair
     * --------------------------------------------------
     */

    printf("[2] Generating Bob's X25519 key pair...\n");

    bob_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (bob_ctx == NULL)
    {
        printf("ERROR: Could not create Bob key context.\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(bob_ctx) <= 0)
    {
        printf("ERROR: Bob key generation initialization failed.\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen(bob_ctx, &bob_key) <= 0)
    {
        printf("ERROR: Bob key generation failed.\n");
        goto cleanup;
    }

    printf("    Bob key pair generated successfully.\n\n");

    /*
     * --------------------------------------------------
     * 3. Extract public keys
     * --------------------------------------------------
     */

    printf("[3] Extracting public keys...\n");

    if (EVP_PKEY_get_raw_public_key(
            alice_key,
            NULL,
            &alice_public_len) <= 0)
    {
        printf("ERROR: Could not determine Alice public key size.\n");
        goto cleanup;
    }

    if (EVP_PKEY_get_raw_public_key(
            bob_key,
            NULL,
            &bob_public_len) <= 0)
    {
        printf("ERROR: Could not determine Bob public key size.\n");
        goto cleanup;
    }

    alice_public = malloc(alice_public_len);
    bob_public = malloc(bob_public_len);

    if (alice_public == NULL || bob_public == NULL)
    {
        printf("ERROR: Memory allocation failed.\n");
        goto cleanup;
    }

    if (EVP_PKEY_get_raw_public_key(
            alice_key,
            alice_public,
            &alice_public_len) <= 0)
    {
        printf("ERROR: Could not extract Alice public key.\n");
        goto cleanup;
    }

    if (EVP_PKEY_get_raw_public_key(
            bob_key,
            bob_public,
            &bob_public_len) <= 0)
    {
        printf("ERROR: Could not extract Bob public key.\n");
        goto cleanup;
    }

    printf("    Alice public key size: %zu bytes\n", alice_public_len);
    printf("    Bob public key size: %zu bytes\n\n", bob_public_len);

    print_hex("    Alice public key: ", alice_public, alice_public_len);
    print_hex("    Bob public key:   ", bob_public, bob_public_len);

    printf("\n");

    /*
     * --------------------------------------------------
     * 4. Alice derives shared secret using Bob's public key
     * --------------------------------------------------
     */

    printf("[4] Alice deriving shared secret...\n");

    alice_derive_ctx = EVP_PKEY_CTX_new(alice_key, NULL);

    if (alice_derive_ctx == NULL)
    {
        printf("ERROR: Could not create Alice derivation context.\n");
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(alice_derive_ctx) <= 0)
    {
        printf("ERROR: Alice derivation initialization failed.\n");
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(alice_derive_ctx, bob_key) <= 0)
    {
        printf("ERROR: Could not set Bob's public key as peer.\n");
        goto cleanup;
    }

    if (EVP_PKEY_derive(
            alice_derive_ctx,
            alice_shared_secret,
            &alice_secret_len) <= 0)
    {
        printf("ERROR: Alice shared secret derivation failed.\n");
        goto cleanup;
    }

    printf("    Alice shared secret generated.\n\n");

    /*
     * --------------------------------------------------
     * 5. Bob derives shared secret using Alice's public key
     * --------------------------------------------------
     */

    printf("[5] Bob deriving shared secret...\n");

    bob_derive_ctx = EVP_PKEY_CTX_new(bob_key, NULL);

    if (bob_derive_ctx == NULL)
    {
        printf("ERROR: Could not create Bob derivation context.\n");
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(bob_derive_ctx) <= 0)
    {
        printf("ERROR: Bob derivation initialization failed.\n");
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(bob_derive_ctx, alice_key) <= 0)
    {
        printf("ERROR: Could not set Alice's public key as peer.\n");
        goto cleanup;
    }

    if (EVP_PKEY_derive(
            bob_derive_ctx,
            bob_shared_secret,
            &bob_secret_len) <= 0)
    {
        printf("ERROR: Bob shared secret derivation failed.\n");
        goto cleanup;
    }

    printf("    Bob shared secret generated.\n\n");

    /*
     * --------------------------------------------------
     * 6. Display shared secrets
     * --------------------------------------------------
     */

    print_hex(
        "Alice shared secret: ",
        alice_shared_secret,
        alice_secret_len);

    print_hex(
        "Bob shared secret:   ",
        bob_shared_secret,
        bob_secret_len);

    printf("\n");

    /*
     * --------------------------------------------------
     * 7. Verify both secrets are identical
     * --------------------------------------------------
     */

    printf("[6] Verifying shared secrets...\n");

    if (alice_secret_len == bob_secret_len &&
        memcmp(
            alice_shared_secret,
            bob_shared_secret,
            alice_secret_len) == 0)
    {
        printf("\n");
        printf("========================================\n");
        printf("       X25519 TEST SUCCESSFUL!\n");
        printf("========================================\n");
        printf("Alice and Bob have the SAME shared secret.\n");
    }
    else
    {
        printf("\n");
        printf("========================================\n");
        printf("       X25519 TEST FAILED!\n");
        printf("========================================\n");
        printf("Alice and Bob have DIFFERENT secrets.\n");
    }

cleanup:

    EVP_PKEY_CTX_free(alice_ctx);
    EVP_PKEY_CTX_free(bob_ctx);

    EVP_PKEY_CTX_free(alice_derive_ctx);
    EVP_PKEY_CTX_free(bob_derive_ctx);

    EVP_PKEY_free(alice_key);
    EVP_PKEY_free(bob_key);

    free(alice_public);
    free(bob_public);

    return 0;
}