#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

/*
 * ============================================================
 * Hybrid PQC Key Exchange
 *
 * X25519 + ML-KEM-768
 *        ↓
 * HKDF-SHA-384
 *        ↓
 * 32-byte Hybrid Session Key
 * ============================================================
 */

#define KEM_ALG OQS_KEM_alg_ml_kem_768
#define HYBRID_KEY_LENGTH 32

void print_hex(
    const char *label,
    const unsigned char *data,
    size_t len)
{
    printf("%s", label);

    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", data[i]);
    }

    printf("\n");
}


/*
 * ============================================================
 * HKDF-SHA-384
 * ============================================================
 */

int derive_hybrid_key(
    const unsigned char *x25519_secret,
    size_t x25519_len,
    const unsigned char *mlkem_secret,
    size_t mlkem_len,
    unsigned char *hybrid_key)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;

    unsigned char *ikm = NULL;

    int result = 0;

    /*
     * --------------------------------------------------------
     * Combine X25519 and ML-KEM secrets
     *
     * IKM =
     *     X25519 Secret || ML-KEM Secret
     * --------------------------------------------------------
     */

    size_t ikm_len = x25519_len + mlkem_len;

    ikm = malloc(ikm_len);

    if (ikm == NULL)
    {
        printf("ERROR: Memory allocation failed.\n");
        goto cleanup;
    }

    memcpy(
        ikm,
        x25519_secret,
        x25519_len);

    memcpy(
        ikm + x25519_len,
        mlkem_secret,
        mlkem_len);


    /*
     * --------------------------------------------------------
     * Create HKDF
     * --------------------------------------------------------
     */

    kdf = EVP_KDF_fetch(
        NULL,
        "HKDF",
        NULL);

    if (kdf == NULL)
    {
        printf("ERROR: Could not create HKDF.\n");
        goto cleanup;
    }

    kdf_ctx = EVP_KDF_CTX_new(kdf);

    if (kdf_ctx == NULL)
    {
        printf("ERROR: Could not create HKDF context.\n");
        goto cleanup;
    }


    /*
     * --------------------------------------------------------
     * HKDF parameters
     *
     * SHA-384
     * Extract + Expand
     *
     * We intentionally omit "salt".
     * HKDF treats an absent salt as a zero-filled salt
     * of the hash length.
     * --------------------------------------------------------
     */

    const char *digest = "SHA384";

    const char *mode = "EXTRACT_AND_EXPAND";

    const char *info_string =
        "HybridPQC-X25519-MLKEM768";

    OSSL_PARAM params[] =
    {
        OSSL_PARAM_construct_utf8_string(
            "digest",
            (char *)digest,
            0),

        OSSL_PARAM_construct_utf8_string(
            "mode",
            (char *)mode,
            0),

        OSSL_PARAM_construct_octet_string(
            "key",
            ikm,
            ikm_len),

        OSSL_PARAM_construct_octet_string(
            "info",
            (void *)info_string,
            strlen(info_string)),

        OSSL_PARAM_construct_end()
    };


    /*
     * --------------------------------------------------------
     * Derive 32-byte hybrid session key
     * --------------------------------------------------------
     */

    if (EVP_KDF_derive(
            kdf_ctx,
            hybrid_key,
            HYBRID_KEY_LENGTH,
            params) <= 0)
    {
        printf("ERROR: HKDF derivation failed.\n");

        /*
         * Print OpenSSL error details
         * to help diagnose future problems.
         */

        ERR_print_errors_fp(stderr);

        goto cleanup;
    }

    result = 1;


cleanup:

    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);

    if (ikm != NULL)
    {
        memset(ikm, 0, ikm_len);
        free(ikm);
    }

    return result;
}


int main(void)
{
    printf("====================================================\n");
    printf("       HYBRID POST-QUANTUM KEY EXCHANGE\n");
    printf("====================================================\n");

    printf("\n");
    printf("Algorithms:\n");
    printf("  Classical : X25519\n");
    printf("  Post-Quantum : ML-KEM-768\n");
    printf("  KDF : HKDF-SHA-384\n");
    printf("  Session Key : 256 bits\n\n");


    /*
     * ========================================================
     * 1. Initialize ML-KEM
     * ========================================================
     */

    printf("[1] Initializing ML-KEM-768...\n");

    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);

    if (kem == NULL)
    {
        printf("ERROR: ML-KEM-768 is unavailable.\n");
        return 1;
    }

    printf("    ML-KEM-768 initialized successfully.\n\n");


    /*
     * ========================================================
     * 2. Allocate ML-KEM memory
     * ========================================================
     */

    uint8_t *mlkem_public_key =
        malloc(kem->length_public_key);

    uint8_t *mlkem_secret_key =
        malloc(kem->length_secret_key);

    uint8_t *mlkem_ciphertext =
        malloc(kem->length_ciphertext);

    uint8_t *alice_mlkem_secret =
        malloc(kem->length_shared_secret);

    uint8_t *bob_mlkem_secret =
        malloc(kem->length_shared_secret);


    if (!mlkem_public_key ||
        !mlkem_secret_key ||
        !mlkem_ciphertext ||
        !alice_mlkem_secret ||
        !bob_mlkem_secret)
    {
        printf("ERROR: ML-KEM memory allocation failed.\n");

        goto cleanup;
    }


    /*
     * ========================================================
     * 3. ML-KEM Key Generation
     * ========================================================
     */

    printf("[2] Generating ML-KEM-768 key pair...\n");

    if (OQS_KEM_keypair(
            kem,
            mlkem_public_key,
            mlkem_secret_key) != OQS_SUCCESS)
    {
        printf("ERROR: ML-KEM key generation failed.\n");
        goto cleanup;
    }

    printf("    ML-KEM key pair generated.\n\n");


    /*
     * ========================================================
     * 4. ML-KEM Encapsulation
     * ========================================================
     */

    printf("[3] Bob encapsulates ML-KEM shared secret...\n");

    if (OQS_KEM_encaps(
            kem,
            mlkem_ciphertext,
            bob_mlkem_secret,
            mlkem_public_key) != OQS_SUCCESS)
    {
        printf("ERROR: ML-KEM encapsulation failed.\n");
        goto cleanup;
    }

    printf("    ML-KEM encapsulation successful.\n\n");


    /*
     * ========================================================
     * 5. ML-KEM Decapsulation
     * ========================================================
     */

    printf("[4] Alice decapsulates ML-KEM shared secret...\n");

    if (OQS_KEM_decaps(
            kem,
            alice_mlkem_secret,
            mlkem_ciphertext,
            mlkem_secret_key) != OQS_SUCCESS)
    {
        printf("ERROR: ML-KEM decapsulation failed.\n");
        goto cleanup;
    }

    printf("    ML-KEM decapsulation successful.\n\n");


    /*
     * ========================================================
     * 6. Verify ML-KEM secrets
     * ========================================================
     */

    printf("[5] Verifying ML-KEM shared secrets...\n");

    if (memcmp(
            alice_mlkem_secret,
            bob_mlkem_secret,
            kem->length_shared_secret) != 0)
    {
        printf("ERROR: ML-KEM shared secrets do not match.\n");
        goto cleanup;
    }

    printf("    ML-KEM shared secrets MATCH.\n\n");


    /*
     * ========================================================
     * 7. Generate X25519 key pairs
     * ========================================================
     */

    printf("[6] Generating X25519 key pairs...\n");

    EVP_PKEY_CTX *alice_x25519_ctx =
        EVP_PKEY_CTX_new_id(
            EVP_PKEY_X25519,
            NULL);

    EVP_PKEY_CTX *bob_x25519_ctx =
        EVP_PKEY_CTX_new_id(
            EVP_PKEY_X25519,
            NULL);

    EVP_PKEY *alice_x25519 = NULL;
    EVP_PKEY *bob_x25519 = NULL;


    if (!alice_x25519_ctx || !bob_x25519_ctx)
    {
        printf("ERROR: X25519 context creation failed.\n");
        EVP_PKEY_CTX_free(alice_x25519_ctx);
        EVP_PKEY_CTX_free(bob_x25519_ctx);
        goto cleanup;
    }


    if (EVP_PKEY_keygen_init(alice_x25519_ctx) <= 0 ||
        EVP_PKEY_keygen(alice_x25519_ctx, &alice_x25519) <= 0)
    {
        printf("ERROR: Alice X25519 key generation failed.\n");

        EVP_PKEY_CTX_free(alice_x25519_ctx);
        EVP_PKEY_CTX_free(bob_x25519_ctx);

        goto cleanup;
    }


    if (EVP_PKEY_keygen_init(bob_x25519_ctx) <= 0 ||
        EVP_PKEY_keygen(bob_x25519_ctx, &bob_x25519) <= 0)
    {
        printf("ERROR: Bob X25519 key generation failed.\n");

        EVP_PKEY_CTX_free(alice_x25519_ctx);
        EVP_PKEY_CTX_free(bob_x25519_ctx);

        EVP_PKEY_free(alice_x25519);

        goto cleanup;
    }


    printf("    X25519 key pairs generated.\n\n");


    EVP_PKEY_CTX_free(alice_x25519_ctx);
    EVP_PKEY_CTX_free(bob_x25519_ctx);


    /*
     * ========================================================
     * 8. Derive X25519 shared secrets
     * ========================================================
     */

    printf("[7] Deriving X25519 shared secrets...\n");

    unsigned char alice_x25519_secret[32];
    unsigned char bob_x25519_secret[32];

    size_t alice_x25519_secret_len =
        sizeof(alice_x25519_secret);

    size_t bob_x25519_secret_len =
        sizeof(bob_x25519_secret);


    EVP_PKEY_CTX *alice_derive =
        EVP_PKEY_CTX_new(
            alice_x25519,
            NULL);

    EVP_PKEY_CTX *bob_derive =
        EVP_PKEY_CTX_new(
            bob_x25519,
            NULL);


    if (!alice_derive || !bob_derive)
    {
        printf("ERROR: X25519 derive context failed.\n");

        EVP_PKEY_CTX_free(alice_derive);
        EVP_PKEY_CTX_free(bob_derive);

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }


    if (EVP_PKEY_derive_init(alice_derive) <= 0 ||
        EVP_PKEY_derive_set_peer(
            alice_derive,
            bob_x25519) <= 0 ||
        EVP_PKEY_derive(
            alice_derive,
            alice_x25519_secret,
            &alice_x25519_secret_len) <= 0)
    {
        printf("ERROR: Alice X25519 derivation failed.\n");

        EVP_PKEY_CTX_free(alice_derive);
        EVP_PKEY_CTX_free(bob_derive);

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }


    if (EVP_PKEY_derive_init(bob_derive) <= 0 ||
        EVP_PKEY_derive_set_peer(
            bob_derive,
            alice_x25519) <= 0 ||
        EVP_PKEY_derive(
            bob_derive,
            bob_x25519_secret,
            &bob_x25519_secret_len) <= 0)
    {
        printf("ERROR: Bob X25519 derivation failed.\n");

        EVP_PKEY_CTX_free(alice_derive);
        EVP_PKEY_CTX_free(bob_derive);

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }


    EVP_PKEY_CTX_free(alice_derive);
    EVP_PKEY_CTX_free(bob_derive);


    printf("    X25519 shared secrets generated.\n\n");


    /*
     * ========================================================
     * 9. Verify X25519 secrets
     * ========================================================
     */

    printf("[8] Verifying X25519 shared secrets...\n");

    if (memcmp(
            alice_x25519_secret,
            bob_x25519_secret,
            32) != 0)
    {
        printf("ERROR: X25519 shared secrets do not match.\n");

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }

    printf("    X25519 shared secrets MATCH.\n\n");


    /*
     * ========================================================
     * 10. Display both component secrets
     * ========================================================
     */

    print_hex(
        "X25519 Secret : ",
        alice_x25519_secret,
        32);

    print_hex(
        "ML-KEM Secret : ",
        alice_mlkem_secret,
        kem->length_shared_secret);

    printf("\n");


    /*
     * ========================================================
     * 11. Derive Hybrid Key using HKDF-SHA-384
     * ========================================================
     */

    printf("[9] Deriving HYBRID SESSION KEY...\n");

    unsigned char alice_hybrid_key[HYBRID_KEY_LENGTH];
    unsigned char bob_hybrid_key[HYBRID_KEY_LENGTH];


    if (!derive_hybrid_key(
            alice_x25519_secret,
            32,
            alice_mlkem_secret,
            kem->length_shared_secret,
            alice_hybrid_key))
    {
        printf("ERROR: Alice hybrid key derivation failed.\n");

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }


    if (!derive_hybrid_key(
            bob_x25519_secret,
            32,
            bob_mlkem_secret,
            kem->length_shared_secret,
            bob_hybrid_key))
    {
        printf("ERROR: Bob hybrid key derivation failed.\n");

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }


    EVP_PKEY_free(alice_x25519);
    EVP_PKEY_free(bob_x25519);


    /*
     * ========================================================
     * 12. Display Hybrid Keys
     * ========================================================
     */

    print_hex(
        "Alice Hybrid Key: ",
        alice_hybrid_key,
        HYBRID_KEY_LENGTH);

    print_hex(
        "Bob Hybrid Key:   ",
        bob_hybrid_key,
        HYBRID_KEY_LENGTH);

    printf("\n");


    /*
     * ========================================================
     * 13. Final Verification
     * ========================================================
     */

    printf("[10] Verifying HYBRID SESSION KEYS...\n");

    if (memcmp(
            alice_hybrid_key,
            bob_hybrid_key,
            HYBRID_KEY_LENGTH) == 0)
    {
        printf("\n");
        printf("====================================================\n");
        printf("       HYBRID PQC TEST SUCCESSFUL!\n");
        printf("====================================================\n");
        printf("X25519 shared secret       : MATCH\n");
        printf("ML-KEM-768 shared secret   : MATCH\n");
        printf("HKDF-SHA-384 derivation    : SUCCESS\n");
        printf("Hybrid session key         : MATCH\n");
        printf("Session key size           : 256 bits\n");
        printf("\n");
        printf("Alice and Bob can now use the SAME\n");
        printf("hybrid session key for secure encryption.\n");
    }
    else
    {
        printf("\n");
        printf("ERROR: Hybrid session keys DO NOT MATCH!\n");
    }


cleanup:

    free(mlkem_public_key);
    free(mlkem_secret_key);
    free(mlkem_ciphertext);
    free(alice_mlkem_secret);
    free(bob_mlkem_secret);

    OQS_KEM_free(kem);

    return 0;
}