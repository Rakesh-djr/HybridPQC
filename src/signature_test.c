#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

int main(void)
{
    OQS_SIG *sig = NULL;

    unsigned char *public_key = NULL;
    unsigned char *secret_key = NULL;
    unsigned char *signature = NULL;

    size_t signature_length = 0;

    const unsigned char message[] =
        "HybridPQC authentication test";

    printf("\n");
    printf("========================================\n");
    printf(" PQ Digital Signature Test\n");
    printf(" ML-DSA\n");
    printf("========================================\n\n");

    /*
     * Create ML-DSA-65
     */
    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if (sig == NULL)
    {
        printf("[TEST] Failed to create ML-DSA-65\n");
        return 1;
    }

    printf("[TEST] Algorithm           : %s\n",
           sig->method_name);

    printf("[TEST] Public key size     : %zu bytes\n",
           sig->length_public_key);

    printf("[TEST] Secret key size     : %zu bytes\n",
           sig->length_secret_key);

    printf("[TEST] Signature size      : %zu bytes\n\n",
           sig->length_signature);

    /*
     * Allocate memory
     */
    public_key =
        malloc(sig->length_public_key);

    secret_key =
        malloc(sig->length_secret_key);

    signature =
        malloc(sig->length_signature);

    if (public_key == NULL ||
        secret_key == NULL ||
        signature == NULL)
    {
        printf("[TEST] Memory allocation failed\n");

        OQS_SIG_free(sig);

        free(public_key);
        free(secret_key);
        free(signature);

        return 1;
    }

    /*
     * Generate signing key pair
     */
    printf("[TEST] Generating ML-DSA keypair...\n");

    if (OQS_SIG_keypair(
            sig,
            public_key,
            secret_key) != OQS_SUCCESS)
    {
        printf("[TEST] Key generation failed\n");

        goto cleanup;
    }

    printf("[TEST] Keypair generation : SUCCESS\n");

    /*
     * Sign message
     */
    printf("[TEST] Signing message...\n");

    if (OQS_SIG_sign(
            sig,
            signature,
            &signature_length,
            message,
            sizeof(message) - 1,
            secret_key) != OQS_SUCCESS)
    {
        printf("[TEST] Signing failed\n");

        goto cleanup;
    }

    printf("[TEST] Signing            : SUCCESS\n");
    printf("[TEST] Signature length   : %zu bytes\n",
           signature_length);

    /*
     * Verify signature
     */
    printf("[TEST] Verifying signature...\n");

    if (OQS_SIG_verify(
            sig,
            message,
            sizeof(message) - 1,
            signature,
            signature_length,
            public_key) != OQS_SUCCESS)
    {
        printf("[TEST] Signature verification failed\n");

        goto cleanup;
    }

    printf("[TEST] Verification       : SUCCESS\n");

    /*
     * Tamper with message
     */
    unsigned char tampered_message[] =
        "HybridPQC authentication tesX";

    printf("[TEST] Testing tamper detection...\n");

    if (OQS_SIG_verify(
            sig,
            tampered_message,
            sizeof(tampered_message) - 1,
            signature,
            signature_length,
            public_key) == OQS_SUCCESS)
    {
        printf("[TEST] ERROR: Tampered message accepted!\n");

        goto cleanup;
    }

    printf("[TEST] Tamper detection   : SUCCESS\n");

    printf("\n");
    printf("========================================\n");
    printf(" PQ SIGNATURE TEST SUCCESSFUL\n");
    printf("========================================\n");
    printf("ML-DSA key generation : SUCCESS\n");
    printf("ML-DSA signing        : SUCCESS\n");
    printf("ML-DSA verification   : SUCCESS\n");
    printf("Tamper detection      : SUCCESS\n");
    printf("========================================\n");

    /*
     * Successful completion
     */
    OQS_SIG_free(sig);

    free(public_key);
    free(secret_key);
    free(signature);

    return 0;

cleanup:

    OQS_SIG_free(sig);

    free(public_key);
    free(secret_key);
    free(signature);

    return 1;
}