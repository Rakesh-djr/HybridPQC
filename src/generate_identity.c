#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include <oqs/oqs.h>

#define KEY_DIRECTORY "C:\\HybridPQC\\keys"

#define PUBLIC_KEY_FILE \
    "C:\\HybridPQC\\keys\\server_mldsa_public.key"

#define SECRET_KEY_FILE \
    "C:\\HybridPQC\\keys\\server_mldsa_secret.key"

static int save_binary_file(
    const char *filename,
    const unsigned char *data,
    size_t length)
{
    FILE *file = fopen(filename, "wb");

    if (file == NULL)
    {
        printf("[ERROR] Could not open file:\n%s\n",
               filename);

        return 0;
    }

    if (fwrite(data, 1, length, file) != length)
    {
        printf("[ERROR] Failed to write file:\n%s\n",
               filename);

        fclose(file);

        return 0;
    }

    fclose(file);

    return 1;
}

int main(void)
{
    OQS_SIG *sig = NULL;

    unsigned char *public_key = NULL;
    unsigned char *secret_key = NULL;

    int result = EXIT_FAILURE;

    printf("\n");
    printf("========================================\n");
    printf(" HybridPQC Bob Identity Generator\n");
    printf(" ML-DSA-65\n");
    printf("========================================\n\n");

    /*
     * Create the ML-DSA-65 object.
     */
    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if (sig == NULL)
    {
        printf(
            "[ERROR] Failed to initialize ML-DSA-65\n");

        goto cleanup;
    }

    printf(
        "[INFO] Algorithm: %s\n",
        sig->method_name);

    printf(
        "[INFO] Public key size: %zu bytes\n",
        sig->length_public_key);

    printf(
        "[INFO] Secret key size: %zu bytes\n",
        sig->length_secret_key);

    /*
     * Create the keys directory.
     *
     * ERROR_ALREADY_EXISTS is fine because the
     * directory may already exist.
     */
    if (!CreateDirectoryA(
            KEY_DIRECTORY,
            NULL))
    {
        DWORD error = GetLastError();

        if (error != ERROR_ALREADY_EXISTS)
        {
            printf(
                "[ERROR] Failed to create key directory\n");

            goto cleanup;
        }
    }

    /*
     * Allocate key memory.
     */
    public_key =
        malloc(sig->length_public_key);

    secret_key =
        malloc(sig->length_secret_key);

    if (public_key == NULL ||
        secret_key == NULL)
    {
        printf(
            "[ERROR] Memory allocation failed\n");

        goto cleanup;
    }

    memset(
        public_key,
        0,
        sig->length_public_key);

    memset(
        secret_key,
        0,
        sig->length_secret_key);

    /*
     * Generate ML-DSA key pair.
     */
    printf(
        "\n[INFO] Generating ML-DSA-65 identity...\n");

    if (OQS_SIG_keypair(
            sig,
            public_key,
            secret_key) != OQS_SUCCESS)
    {
        printf(
            "[ERROR] ML-DSA key generation failed\n");

        goto cleanup;
    }

    printf(
        "[SUCCESS] ML-DSA-65 identity generated\n");

    /*
     * Save public key.
     */
    printf(
        "[INFO] Saving public key...\n");

    if (!save_binary_file(
            PUBLIC_KEY_FILE,
            public_key,
            sig->length_public_key))
    {
        goto cleanup;
    }

    printf(
        "[SUCCESS] Public key saved:\n%s\n",
        PUBLIC_KEY_FILE);

    /*
     * Save secret key.
     */
    printf(
        "[INFO] Saving secret key...\n");

    if (!save_binary_file(
            SECRET_KEY_FILE,
            secret_key,
            sig->length_secret_key))
    {
        goto cleanup;
    }

    printf(
        "[SUCCESS] Secret key saved:\n%s\n",
        SECRET_KEY_FILE);

    printf("\n");
    printf("========================================\n");
    printf(" BOB IDENTITY CREATED SUCCESSFULLY\n");
    printf("========================================\n");
    printf("Algorithm : ML-DSA-65\n");
    printf("Public key: server_mldsa_public.key\n");
    printf("Secret key: server_mldsa_secret.key\n");
    printf("========================================\n");

    result = EXIT_SUCCESS;

cleanup:

    if (public_key != NULL)
    {
        SecureZeroMemory(
            public_key,
            sig != NULL
                ? sig->length_public_key
                : 0);

        free(public_key);
    }

    if (secret_key != NULL)
    {
        SecureZeroMemory(
            secret_key,
            sig != NULL
                ? sig->length_secret_key
                : 0);

        free(secret_key);
    }

    if (sig != NULL)
    {
        OQS_SIG_free(sig);
    }

    return result;
}