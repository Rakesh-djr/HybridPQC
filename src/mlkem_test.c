#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#define KEM_ALG OQS_KEM_alg_ml_kem_768

int main(void) {

    printf("========================================\n");
    printf("       ML-KEM-768 TEST PROGRAM\n");
    printf("========================================\n\n");

    /* Create ML-KEM object */
    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);

    if (kem == NULL) {
        printf("ERROR: ML-KEM-768 is not available.\n");
        return 1;
    }

    printf("Algorithm: %s\n", kem->method_name);
    printf("Public key size: %zu bytes\n", kem->length_public_key);
    printf("Secret key size: %zu bytes\n", kem->length_secret_key);
    printf("Ciphertext size: %zu bytes\n", kem->length_ciphertext);
    printf("Shared secret size: %zu bytes\n\n", kem->length_shared_secret);

    /* Allocate memory */
    uint8_t *public_key =
        malloc(kem->length_public_key);

    uint8_t *secret_key =
        malloc(kem->length_secret_key);

    uint8_t *ciphertext =
        malloc(kem->length_ciphertext);

    uint8_t *alice_shared_secret =
        malloc(kem->length_shared_secret);

    uint8_t *bob_shared_secret =
        malloc(kem->length_shared_secret);

    if (!public_key ||
        !secret_key ||
        !ciphertext ||
        !alice_shared_secret ||
        !bob_shared_secret) {

        printf("ERROR: Memory allocation failed.\n");

        free(public_key);
        free(secret_key);
        free(ciphertext);
        free(alice_shared_secret);
        free(bob_shared_secret);

        OQS_KEM_free(kem);

        return 1;
    }

    /*
     * STEP 1
     * Alice generates public and secret keys.
     */
    printf("[1] Generating ML-KEM key pair...\n");

    if (OQS_KEM_keypair(
            kem,
            public_key,
            secret_key) != OQS_SUCCESS) {

        printf("ERROR: Key generation failed.\n");

        return 1;
    }

    printf("    Key generation successful.\n\n");

    /*
     * STEP 2
     * Bob uses Alice's public key to create:
     *
     * ciphertext
     * +
     * shared secret
     */
    printf("[2] Bob encapsulates shared secret...\n");

    if (OQS_KEM_encaps(
            kem,
            ciphertext,
            bob_shared_secret,
            public_key) != OQS_SUCCESS) {

        printf("ERROR: Encapsulation failed.\n");

        return 1;
    }

    printf("    Encapsulation successful.\n\n");

    /*
     * STEP 3
     * Alice uses her secret key and Bob's ciphertext
     * to recover the same shared secret.
     */
    printf("[3] Alice decapsulates shared secret...\n");

    if (OQS_KEM_decaps(
            kem,
            alice_shared_secret,
            ciphertext,
            secret_key) != OQS_SUCCESS) {

        printf("ERROR: Decapsulation failed.\n");

        return 1;
    }

    printf("    Decapsulation successful.\n\n");

    /*
     * STEP 4
     * Verify that both sides calculated the
     * same shared secret.
     */
    printf("[4] Verifying shared secrets...\n");

    if (memcmp(
            alice_shared_secret,
            bob_shared_secret,
            kem->length_shared_secret) == 0) {

        printf("\n");
        printf("========================================\n");
        printf("       ML-KEM TEST SUCCESSFUL!\n");
        printf("========================================\n");
        printf("Alice and Bob have the SAME shared secret.\n");

    } else {

        printf("\n");
        printf("ERROR: Shared secrets DO NOT match!\n");

    }

    /*
     * Cleanup
     */
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(alice_shared_secret);
    free(bob_shared_secret);

    OQS_KEM_free(kem);

    return 0;
}