#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/*
 * ============================================================
 * Hybrid Post-Quantum Secure Communication
 *
 * Classical      : X25519
 * Post-Quantum   : ML-KEM-768
 * KDF            : HKDF-SHA-384
 * Encryption     : AES-256-GCM
 *
 * Protocol:
 *
 * X25519 shared secret
 *          +
 * ML-KEM shared secret
 *          |
 *          v
 *    HKDF-SHA-384
 *          |
 *          v
 *   256-bit hybrid key
 *          |
 *          v
 *     AES-256-GCM
 *          |
 *          v
 * Authenticated ciphertext
 * ============================================================
 */

#define KEM_ALG OQS_KEM_alg_ml_kem_768

#define HYBRID_KEY_LENGTH 32

#define GCM_NONCE_LENGTH 12
#define GCM_TAG_LENGTH 16

#define MAX_MESSAGE_LENGTH 4096


/*
 * ============================================================
 * Utility
 * ============================================================
 */

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
 *
 * Combines:
 *
 * X25519 shared secret
 * +
 * ML-KEM-768 shared secret
 *
 * into one 256-bit hybrid session key.
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

    size_t ikm_len =
        x25519_len + mlkem_len;


    /*
     * Allocate memory for:
     *
     * IKM =
     * X25519 secret || ML-KEM secret
     */

    ikm = malloc(ikm_len);

    if (ikm == NULL)
    {
        printf("ERROR: Could not allocate HKDF input memory.\n");
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
     * Create HKDF object
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


    /*
     * Create HKDF context
     */

    kdf_ctx = EVP_KDF_CTX_new(kdf);

    if (kdf_ctx == NULL)
    {
        printf("ERROR: Could not create HKDF context.\n");
        goto cleanup;
    }


    /*
     * HKDF configuration
     */

    const char *digest = "SHA384";

    const char *mode =
        "EXTRACT_AND_EXPAND";

    const char *info_string =
        "HybridPQC-X25519-MLKEM768-AES256GCM";


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
     * Derive 32-byte key
     */

    if (EVP_KDF_derive(
            kdf_ctx,
            hybrid_key,
            HYBRID_KEY_LENGTH,
            params) <= 0)
    {
        printf("ERROR: HKDF derivation failed.\n");

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


/*
 * ============================================================
 * AES-256-GCM ENCRYPTION
 * ============================================================
 */

int aes_gcm_encrypt(
    const unsigned char *plaintext,
    int plaintext_len,
    const unsigned char *key,
    const unsigned char *nonce,
    unsigned char *ciphertext,
    unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = NULL;

    int len = 0;
    int ciphertext_len = 0;


    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
    {
        printf("ERROR: Could not create AES encryption context.\n");
        return 0;
    }


    /*
     * Initialize AES-256-GCM
     */

    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1)
    {
        printf("ERROR: AES-GCM initialization failed.\n");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }


    /*
     * Set key and nonce
     */

    if (EVP_EncryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce) != 1)
    {
        printf("ERROR: Could not set AES key/nonce.\n");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }


    /*
     * Encrypt plaintext
     */

    if (EVP_EncryptUpdate(
            ctx,
            ciphertext,
            &len,
            plaintext,
            plaintext_len) != 1)
    {
        printf("ERROR: AES encryption failed.\n");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }


    ciphertext_len = len;


    /*
     * Finalize encryption
     */

    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + len,
            &len) != 1)
    {
        printf("ERROR: AES encryption finalization failed.\n");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }


    ciphertext_len += len;


    /*
     * Obtain authentication tag
     */

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            GCM_TAG_LENGTH,
            tag) != 1)
    {
        printf("ERROR: Could not obtain GCM authentication tag.\n");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }


    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


/*
 * ============================================================
 * AES-256-GCM DECRYPTION
 * ============================================================
 */

int aes_gcm_decrypt(
    const unsigned char *ciphertext,
    int ciphertext_len,
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *tag,
    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;

    int len = 0;
    int plaintext_len = 0;


    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
    {
        printf("ERROR: Could not create AES decryption context.\n");
        return 0;
    }


    /*
     * Initialize AES-256-GCM
     */

    if (EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1)
    {
        printf("ERROR: AES-GCM decryption initialization failed.\n");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }


    /*
     * Set key and nonce
     */

    if (EVP_DecryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce) != 1)
    {
        printf("ERROR: Could not set AES key/nonce.\n");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }


    /*
     * Decrypt ciphertext
     */

    if (EVP_DecryptUpdate(
            ctx,
            plaintext,
            &len,
            ciphertext,
            ciphertext_len) != 1)
    {
        printf("ERROR: AES decryption failed.\n");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }


    plaintext_len = len;


    /*
     * Set authentication tag
     */

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            GCM_TAG_LENGTH,
            (void *)tag) != 1)
    {
        printf("ERROR: Could not set GCM authentication tag.\n");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }


    /*
     * Finalization verifies authentication tag.
     */

    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext + len,
            &len) <= 0)
    {
        printf("ERROR: AES-GCM authentication FAILED.\n");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }


    plaintext_len += len;


    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


/*
 * ============================================================
 * MAIN
 * ============================================================
 */

int main(void)
{
    printf("\n");
    printf("============================================================\n");
    printf("       HYBRID POST-QUANTUM SECURE CHANNEL\n");
    printf("============================================================\n");

    printf("\n");
    printf("Classical Algorithm : X25519\n");
    printf("Post-Quantum        : ML-KEM-768\n");
    printf("Key Derivation      : HKDF-SHA-384\n");
    printf("Encryption          : AES-256-GCM\n");
    printf("Hybrid Key          : 256 bits\n");


    /*
     * ========================================================
     * 1. Initialize ML-KEM
     * ========================================================
     */

    printf("\n------------------------------------------------------------\n");
    printf("[1] Initializing ML-KEM-768...\n");

    OQS_KEM *kem =
        OQS_KEM_new(KEM_ALG);

    if (kem == NULL)
    {
        printf("ERROR: ML-KEM-768 unavailable.\n");
        return 1;
    }

    printf("    ML-KEM-768 initialized successfully.\n");


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

        free(mlkem_public_key);
        free(mlkem_secret_key);
        free(mlkem_ciphertext);
        free(alice_mlkem_secret);
        free(bob_mlkem_secret);

        OQS_KEM_free(kem);

        return 1;
    }


    /*
     * ========================================================
     * 3. ML-KEM Key Generation
     * ========================================================
     */

    printf("\n[2] Alice generating ML-KEM-768 key pair...\n");

    if (OQS_KEM_keypair(
            kem,
            mlkem_public_key,
            mlkem_secret_key) != OQS_SUCCESS)
    {
        printf("ERROR: ML-KEM key generation failed.\n");
        goto cleanup;
    }

    printf("    ML-KEM key pair generated.\n");


    /*
     * ========================================================
     * 4. Bob encapsulates
     * ========================================================
     */

    printf("\n[3] Bob encapsulating ML-KEM shared secret...\n");

    if (OQS_KEM_encaps(
            kem,
            mlkem_ciphertext,
            bob_mlkem_secret,
            mlkem_public_key) != OQS_SUCCESS)
    {
        printf("ERROR: ML-KEM encapsulation failed.\n");
        goto cleanup;
    }

    printf("    ML-KEM encapsulation successful.\n");


    /*
     * ========================================================
     * 5. Alice decapsulates
     * ========================================================
     */

    printf("\n[4] Alice decapsulating ML-KEM ciphertext...\n");

    if (OQS_KEM_decaps(
            kem,
            alice_mlkem_secret,
            mlkem_ciphertext,
            mlkem_secret_key) != OQS_SUCCESS)
    {
        printf("ERROR: ML-KEM decapsulation failed.\n");
        goto cleanup;
    }

    printf("    ML-KEM decapsulation successful.\n");


    /*
     * ========================================================
     * 6. Verify ML-KEM secret
     * ========================================================
     */

    printf("\n[5] Verifying ML-KEM shared secrets...\n");

    if (memcmp(
            alice_mlkem_secret,
            bob_mlkem_secret,
            kem->length_shared_secret) != 0)
    {
        printf("ERROR: ML-KEM shared secrets DO NOT MATCH.\n");
        goto cleanup;
    }

    printf("    ML-KEM shared secrets MATCH.\n");


    /*
     * ========================================================
     * 7. Generate X25519 keys
     * ========================================================
     */

    printf("\n[6] Generating X25519 key pairs...\n");

    EVP_PKEY *alice_x25519 = NULL;
    EVP_PKEY *bob_x25519 = NULL;

    EVP_PKEY_CTX *alice_x25519_ctx =
        EVP_PKEY_CTX_new_id(
            EVP_PKEY_X25519,
            NULL);

    EVP_PKEY_CTX *bob_x25519_ctx =
        EVP_PKEY_CTX_new_id(
            EVP_PKEY_X25519,
            NULL);


    if (!alice_x25519_ctx ||
        !bob_x25519_ctx)
    {
        printf("ERROR: X25519 context creation failed.\n");

        EVP_PKEY_CTX_free(alice_x25519_ctx);
        EVP_PKEY_CTX_free(bob_x25519_ctx);

        goto cleanup;
    }


    if (EVP_PKEY_keygen_init(
            alice_x25519_ctx) <= 0 ||
        EVP_PKEY_keygen(
            alice_x25519_ctx,
            &alice_x25519) <= 0)
    {
        printf("ERROR: Alice X25519 key generation failed.\n");

        EVP_PKEY_CTX_free(alice_x25519_ctx);
        EVP_PKEY_CTX_free(bob_x25519_ctx);

        goto cleanup;
    }


    if (EVP_PKEY_keygen_init(
            bob_x25519_ctx) <= 0 ||
        EVP_PKEY_keygen(
            bob_x25519_ctx,
            &bob_x25519) <= 0)
    {
        printf("ERROR: Bob X25519 key generation failed.\n");

        EVP_PKEY_CTX_free(alice_x25519_ctx);
        EVP_PKEY_CTX_free(bob_x25519_ctx);

        EVP_PKEY_free(alice_x25519);

        goto cleanup;
    }


    EVP_PKEY_CTX_free(alice_x25519_ctx);
    EVP_PKEY_CTX_free(bob_x25519_ctx);

    printf("    X25519 key pairs generated.\n");


    /*
     * ========================================================
     * 8. Derive X25519 shared secrets
     * ========================================================
     */

    printf("\n[7] Deriving X25519 shared secrets...\n");

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


    if (!alice_derive ||
        !bob_derive)
    {
        printf("ERROR: X25519 derive context creation failed.\n");

        EVP_PKEY_CTX_free(alice_derive);
        EVP_PKEY_CTX_free(bob_derive);

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }


    if (EVP_PKEY_derive_init(
            alice_derive) <= 0 ||
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


    if (EVP_PKEY_derive_init(
            bob_derive) <= 0 ||
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

    printf("    X25519 shared secrets generated.\n");


    /*
     * ========================================================
     * 9. Verify X25519
     * ========================================================
     */

    printf("\n[8] Verifying X25519 shared secrets...\n");

    if (memcmp(
            alice_x25519_secret,
            bob_x25519_secret,
            32) != 0)
    {
        printf("ERROR: X25519 shared secrets DO NOT MATCH.\n");

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }

    printf("    X25519 shared secrets MATCH.\n");


    /*
     * ========================================================
     * 10. Derive hybrid session keys
     * ========================================================
     */

    printf("\n[9] Deriving hybrid session keys...\n");

    unsigned char alice_hybrid_key[HYBRID_KEY_LENGTH];
    unsigned char bob_hybrid_key[HYBRID_KEY_LENGTH];


    if (!derive_hybrid_key(
            alice_x25519_secret,
            sizeof(alice_x25519_secret),
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
            sizeof(bob_x25519_secret),
            bob_mlkem_secret,
            kem->length_shared_secret,
            bob_hybrid_key))
    {
        printf("ERROR: Bob hybrid key derivation failed.\n");

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }


    printf("    HKDF-SHA-384 derivation successful.\n");


    /*
     * ========================================================
     * 11. Verify hybrid keys
     * ========================================================
     */

    printf("\n[10] Verifying hybrid session keys...\n");

    if (memcmp(
            alice_hybrid_key,
            bob_hybrid_key,
            HYBRID_KEY_LENGTH) != 0)
    {
        printf("ERROR: Hybrid session keys DO NOT MATCH.\n");

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }

    printf("    Alice and Bob have the SAME hybrid key.\n");

    print_hex(
        "    Hybrid Key: ",
        alice_hybrid_key,
        HYBRID_KEY_LENGTH);


    /*
     * ========================================================
     * 12. Generate AES-GCM nonce
     * ========================================================
     */

    printf("\n[11] Generating AES-256-GCM nonce...\n");

    unsigned char nonce[GCM_NONCE_LENGTH];

    if (RAND_bytes(
            nonce,
            GCM_NONCE_LENGTH) != 1)
    {
        printf("ERROR: Nonce generation failed.\n");

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }

    printf("    Random nonce generated.\n");

    print_hex(
        "    Nonce: ",
        nonce,
        GCM_NONCE_LENGTH);


    /*
     * ========================================================
     * 13. Message
     * ========================================================
     */

    const unsigned char message[] =
        "Hello Bob! This message is protected "
        "using Hybrid Post-Quantum Cryptography.";

    int message_len =
        (int)strlen(
            (const char *)message);


    printf("\n[12] Alice's plaintext:\n");
    printf("    %s\n", message);


    /*
     * ========================================================
     * 14. Encrypt
     * ========================================================
     */

    printf("\n[13] Alice encrypting message...\n");

    unsigned char ciphertext[MAX_MESSAGE_LENGTH];

    unsigned char tag[GCM_TAG_LENGTH];

    memset(
        ciphertext,
        0,
        sizeof(ciphertext));

    memset(
        tag,
        0,
        sizeof(tag));


    int ciphertext_len =
        aes_gcm_encrypt(
            message,
            message_len,
            alice_hybrid_key,
            nonce,
            ciphertext,
            tag);


    if (ciphertext_len <= 0)
    {
        printf("ERROR: Message encryption failed.\n");

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }


    printf("    Encryption successful.\n");

    print_hex(
        "    Ciphertext: ",
        ciphertext,
        ciphertext_len);

    print_hex(
        "    Auth Tag:   ",
        tag,
        GCM_TAG_LENGTH);


    /*
     * ========================================================
     * 15. Bob decrypts
     * ========================================================
     */

    printf("\n[14] Bob decrypting message...\n");

    unsigned char decrypted[MAX_MESSAGE_LENGTH];

    memset(
        decrypted,
        0,
        sizeof(decrypted));


    int decrypted_len =
        aes_gcm_decrypt(
            ciphertext,
            ciphertext_len,
            bob_hybrid_key,
            nonce,
            tag,
            decrypted);


    if (decrypted_len <= 0)
    {
        printf("ERROR: Bob could not decrypt the message.\n");

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }


    decrypted[decrypted_len] = '\0';


    printf("    Decryption successful.\n");

    printf("    Bob received:\n");
    printf("    %s\n", decrypted);


    /*
     * ========================================================
     * 16. Verify original message
     * ========================================================
     */

    printf("\n[15] Verifying decrypted message...\n");

    if (decrypted_len == message_len &&
        memcmp(
            message,
            decrypted,
            message_len) == 0)
    {
        printf("    Message MATCH.\n");
    }
    else
    {
        printf("    ERROR: Message does not match.\n");

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }


    /*
     * ========================================================
     * 17. Tampering attack simulation
     * ========================================================
     */

    printf("\n[16] Simulating ciphertext tampering...\n");

    /*
     * Modify one ciphertext byte.
     */

    ciphertext[0] ^= 0x01;

    printf("    One byte of ciphertext was modified.\n");


    memset(
        decrypted,
        0,
        sizeof(decrypted));


    int tampered_result =
        aes_gcm_decrypt(
            ciphertext,
            ciphertext_len,
            bob_hybrid_key,
            nonce,
            tag,
            decrypted);


    if (tampered_result <= 0)
    {
        printf("    Tampering detected successfully.\n");
        printf("    AES-256-GCM rejected the modified ciphertext.\n");
    }
    else
    {
        printf("    SECURITY ERROR!\n");
        printf("    Modified ciphertext was accepted.\n");

        EVP_PKEY_free(alice_x25519);
        EVP_PKEY_free(bob_x25519);

        goto cleanup;
    }


    /*
     * ========================================================
     * 18. Final result
     * ========================================================
     */

    EVP_PKEY_free(alice_x25519);
    EVP_PKEY_free(bob_x25519);


    printf("\n");
    printf("============================================================\n");
    printf("       HYBRID SECURE CHANNEL TEST SUCCESSFUL!\n");
    printf("============================================================\n");

    printf("\n");
    printf("X25519 shared secret       : MATCH\n");
    printf("ML-KEM-768 shared secret   : MATCH\n");
    printf("HKDF-SHA-384               : SUCCESS\n");
    printf("Hybrid session key         : MATCH\n");
    printf("AES-256-GCM encryption     : SUCCESS\n");
    printf("AES-256-GCM decryption     : SUCCESS\n");
    printf("Authentication             : SUCCESS\n");
    printf("Tampering detection        : SUCCESS\n");

    printf("\n");
    printf("============================================================\n");
    printf("       END-TO-END SECURITY VERIFIED\n");
    printf("============================================================\n");

    printf("\nAlice and Bob successfully established\n");
    printf("a shared hybrid cryptographic key and\n");
    printf("securely exchanged an authenticated message.\n");

    printf("\n");

cleanup:

    free(mlkem_public_key);
    free(mlkem_secret_key);
    free(mlkem_ciphertext);
    free(alice_mlkem_secret);
    free(bob_mlkem_secret);

    OQS_KEM_free(kem);

    return 0;
}