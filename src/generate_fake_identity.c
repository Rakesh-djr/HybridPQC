#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

#define FAKE_PUBLIC_KEY_FILE "C:\\HybridPQC\\keys\\fake_bob_public.key"
#define FAKE_SECRET_KEY_FILE "C:\\HybridPQC\\keys\\fake_bob_secret.key"

int main(void)
{
    OQS_SIG *sig = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;

    printf("===============================================\n");
    printf("   GENERATING FAKE BOB ML-DSA-65 IDENTITY\n");
    printf("===============================================\n\n");

    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if (sig == NULL)
    {
        printf("[-] Failed to initialize ML-DSA-65\n");
        return EXIT_FAILURE;
    }

    public_key = malloc(sig->length_public_key);
    secret_key = malloc(sig->length_secret_key);

    if (public_key == NULL || secret_key == NULL)
    {
        printf("[-] Memory allocation failed\n");

        free(public_key);
        free(secret_key);
        OQS_SIG_free(sig);

        return EXIT_FAILURE;
    }

    printf("[+] ML-DSA-65 initialized\n");
    printf("[+] Public key size : %zu bytes\n", sig->length_public_key);
    printf("[+] Secret key size : %zu bytes\n", sig->length_secret_key);

    if (OQS_SIG_keypair(
            sig,
            public_key,
            secret_key) != OQS_SUCCESS)
    {
        printf("[-] ML-DSA-65 key generation failed\n");

        free(public_key);
        free(secret_key);
        OQS_SIG_free(sig);

        return EXIT_FAILURE;
    }

    printf("[+] Fake Bob ML-DSA-65 key pair generated\n");

    FILE *fp = fopen(FAKE_PUBLIC_KEY_FILE, "wb");

    if (fp == NULL)
    {
        printf("[-] Failed to create fake public key file\n");

        free(public_key);
        free(secret_key);
        OQS_SIG_free(sig);

        return EXIT_FAILURE;
    }

    fwrite(
        public_key,
        1,
        sig->length_public_key,
        fp
    );

    fclose(fp);

    fp = fopen(FAKE_SECRET_KEY_FILE, "wb");

    if (fp == NULL)
    {
        printf("[-] Failed to create fake secret key file\n");

        free(public_key);
        free(secret_key);
        OQS_SIG_free(sig);

        return EXIT_FAILURE;
    }

    fwrite(
        secret_key,
        1,
        sig->length_secret_key,
        fp
    );

    fclose(fp);

    printf("[+] Fake public key saved:\n");
    printf("    %s\n", FAKE_PUBLIC_KEY_FILE);

    printf("[+] Fake secret key saved:\n");
    printf("    %s\n", FAKE_SECRET_KEY_FILE);

    printf("\n===============================================\n");
    printf("       FAKE IDENTITY GENERATION COMPLETE\n");
    printf("===============================================\n");

    free(public_key);
    free(secret_key);
    OQS_SIG_free(sig);

    return EXIT_SUCCESS;
}