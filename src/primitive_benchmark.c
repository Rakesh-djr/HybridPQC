#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#define WARMUP_BATCHES 5
#define MEASURED_BATCHES 30
#define OPERATIONS_PER_BATCH 100
#define AES_KEY_SIZE 32
#define AES_NONCE_SIZE 12
#define AES_TAG_SIZE 16

typedef int (*benchmark_operation)(void *state);

typedef struct
{
    EVP_PKEY_CTX *keygen_context;
    EVP_PKEY *peer_key;
    EVP_PKEY *private_key;
    EVP_PKEY_CTX *derive_context;
    unsigned char peer_public[32];
    unsigned char shared_secret[32];
} X25519State;

typedef struct
{
    OQS_KEM *kem;
    unsigned char *public_key;
    unsigned char *secret_key;
    unsigned char *ciphertext;
    unsigned char *shared_secret;
} KemState;

typedef struct
{
    OQS_SIG *sig;
    unsigned char *public_key;
    unsigned char *secret_key;
    unsigned char *signature;
    size_t signature_length;
    const unsigned char *message;
    size_t message_length;
} SignatureState;

typedef struct
{
    EVP_KDF_CTX *context;
    OSSL_PARAM *params;
    unsigned char input[64];
    unsigned char info[64];
    size_t info_length;
    unsigned char output[32];
} HkdfState;

typedef struct
{
    EVP_CIPHER_CTX *context;
    unsigned char key[AES_KEY_SIZE];
    unsigned char nonce[AES_NONCE_SIZE];
    unsigned char tag[AES_TAG_SIZE];
    unsigned char *input;
    unsigned char *output;
    int input_length;
    int output_length;
    uint64_t nonce_counter;
    int decrypt;
} AesState;

static double qpc_seconds(LARGE_INTEGER start, LARGE_INTEGER finish,
                          LARGE_INTEGER frequency)
{
    return (double)(finish.QuadPart - start.QuadPart) /
           (double)frequency.QuadPart;
}

static int measure(const char *name, benchmark_operation operation,
                   void *state, LARGE_INTEGER frequency)
{
    double samples[MEASURED_BATCHES];
    LARGE_INTEGER start;
    LARGE_INTEGER finish;
    double sum = 0.0;
    double minimum;
    double maximum;
    double variance = 0.0;
    int batch;
    int operation_index;

    for (batch = 0; batch < WARMUP_BATCHES; ++batch)
    {
        for (operation_index = 0;
             operation_index < OPERATIONS_PER_BATCH;
             ++operation_index)
        {
            if (operation(state) != 0)
            {
                fprintf(stderr, "Benchmark operation failed: %s\n", name);
                return -1;
            }
        }
    }

    for (batch = 0; batch < MEASURED_BATCHES; ++batch)
    {
        QueryPerformanceCounter(&start);

        for (operation_index = 0;
             operation_index < OPERATIONS_PER_BATCH;
             ++operation_index)
        {
            if (operation(state) != 0)
            {
                fprintf(stderr, "Benchmark operation failed: %s\n", name);
                return -1;
            }
        }

        QueryPerformanceCounter(&finish);
        samples[batch] = qpc_seconds(start, finish, frequency) *
                         1000000.0 / OPERATIONS_PER_BATCH;
        sum += samples[batch];
    }

    minimum = samples[0];
    maximum = samples[0];

    for (batch = 0; batch < MEASURED_BATCHES; ++batch)
    {
        if (samples[batch] < minimum)
        {
            minimum = samples[batch];
        }
        if (samples[batch] > maximum)
        {
            maximum = samples[batch];
        }
    }

    sum /= MEASURED_BATCHES;

    for (batch = 0; batch < MEASURED_BATCHES; ++batch)
    {
        double difference = samples[batch] - sum;
        variance += difference * difference;
    }

    variance /= MEASURED_BATCHES;

    printf("%s,%.3f,%.3f,%.3f,%.3f,%d\n",
           name, sum, minimum, maximum, sqrt(variance),
           MEASURED_BATCHES * OPERATIONS_PER_BATCH);
    return 0;
}

static int x25519_keygen(void *opaque)
{
    X25519State *state = (X25519State *)opaque;
    EVP_PKEY *key = NULL;

    if (EVP_PKEY_keygen(state->keygen_context, &key) <= 0)
    {
        return -1;
    }

    EVP_PKEY_free(key);
    return 0;
}

static int x25519_keygen_fresh_context(void *opaque)
{
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;
    int result = -1;

    (void)opaque;
    context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (context != NULL &&
        EVP_PKEY_keygen_init(context) > 0 &&
        EVP_PKEY_keygen(context, &key) > 0)
    {
        result = 0;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(context);
    return result;
}

static int x25519_derive(void *opaque)
{
    X25519State *state = (X25519State *)opaque;
    size_t secret_length = sizeof(state->shared_secret);

    if (EVP_PKEY_derive_init(state->derive_context) <= 0 ||
        EVP_PKEY_derive_set_peer(state->derive_context,
                                 state->peer_key) <= 0 ||
        EVP_PKEY_derive(state->derive_context,
                        state->shared_secret,
                        &secret_length) <= 0 ||
        secret_length != sizeof(state->shared_secret))
    {
        return -1;
    }

    return 0;
}

static int x25519_derive_fresh_context(void *opaque)
{
    X25519State *state = (X25519State *)opaque;
    EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, NULL, state->peer_public,
        sizeof(state->peer_public));
    EVP_PKEY_CTX *context = NULL;
    size_t secret_length = sizeof(state->shared_secret);
    int result = -1;

    if (peer_key != NULL)
    {
        context = EVP_PKEY_CTX_new(state->private_key, NULL);
    }
    if (context != NULL &&
        EVP_PKEY_derive_init(context) > 0 &&
        EVP_PKEY_derive_set_peer(context, peer_key) > 0 &&
        EVP_PKEY_derive(context, state->shared_secret,
                        &secret_length) > 0 &&
        secret_length == sizeof(state->shared_secret))
    {
        result = 0;
    }

    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer_key);
    return result;
}

static int kem_keygen(void *opaque)
{
    KemState *state = (KemState *)opaque;
    return OQS_KEM_keypair(state->kem,
                           state->public_key,
                           state->secret_key) == OQS_SUCCESS ? 0 : -1;
}

static int kem_encaps(void *opaque)
{
    KemState *state = (KemState *)opaque;
    return OQS_KEM_encaps(state->kem,
                          state->ciphertext,
                          state->shared_secret,
                          state->public_key) == OQS_SUCCESS ? 0 : -1;
}

static int kem_decaps(void *opaque)
{
    KemState *state = (KemState *)opaque;
    return OQS_KEM_decaps(state->kem,
                          state->shared_secret,
                          state->ciphertext,
                          state->secret_key) == OQS_SUCCESS ? 0 : -1;
}

static int sig_keygen(void *opaque)
{
    SignatureState *state = (SignatureState *)opaque;
    return OQS_SIG_keypair(state->sig,
                           state->public_key,
                           state->secret_key) == OQS_SUCCESS ? 0 : -1;
}

static int sig_sign(void *opaque)
{
    SignatureState *state = (SignatureState *)opaque;
    return OQS_SIG_sign(state->sig,
                        state->signature,
                        &state->signature_length,
                        state->message,
                        state->message_length,
                        state->secret_key) == OQS_SUCCESS ? 0 : -1;
}

static int sig_verify(void *opaque)
{
    SignatureState *state = (SignatureState *)opaque;
    return OQS_SIG_verify(state->sig,
                          state->message,
                          state->message_length,
                          state->signature,
                          state->signature_length,
                          state->public_key) == OQS_SUCCESS ? 0 : -1;
}

static int hkdf_derive(void *opaque)
{
    HkdfState *state = (HkdfState *)opaque;
    return EVP_KDF_derive(state->context,
                          state->output,
                          sizeof(state->output),
                          state->params) > 0 ? 0 : -1;
}

static int hkdf_full_helper(void *opaque)
{
    HkdfState *state = (HkdfState *)opaque;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *context = NULL;
    OSSL_PARAM params[5];
    int result = -1;

    if (kdf == NULL)
    {
        return -1;
    }

    context = EVP_KDF_CTX_new(kdf);
    if (context != NULL)
    {
        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_MODE, "EXTRACT_AND_EXPAND", 0);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST, "SHA384", 0);
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, state->input, sizeof(state->input));
        params[3] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, state->info, state->info_length);
        params[4] = OSSL_PARAM_construct_end();
        result = EVP_KDF_derive(context, state->output,
                                sizeof(state->output), params) > 0 ? 0 : -1;
    }

    EVP_KDF_CTX_free(context);
    EVP_KDF_free(kdf);
    return result;
}

static void increment_nonce(unsigned char nonce[AES_NONCE_SIZE],
                            uint64_t counter)
{
    int index;

    for (index = 0; index < 8; ++index)
    {
        nonce[AES_NONCE_SIZE - 1 - index] =
            (unsigned char)(counter >> (index * 8));
    }
}

static int aes_operation(void *opaque)
{
    AesState *state = (AesState *)opaque;
    int first_length = 0;
    int final_length = 0;

    if (!state->decrypt)
    {
        increment_nonce(state->nonce, ++state->nonce_counter);
        if (EVP_CIPHER_CTX_reset(state->context) != 1 ||
            EVP_EncryptInit_ex(state->context, EVP_aes_256_gcm(),
                               NULL, state->key, state->nonce) != 1 ||
            EVP_EncryptUpdate(state->context, state->output,
                              &first_length, state->input,
                              state->input_length) != 1 ||
            EVP_EncryptFinal_ex(state->context,
                                state->output + first_length,
                                &final_length) != 1 ||
            EVP_CIPHER_CTX_ctrl(state->context,
                                EVP_CTRL_GCM_GET_TAG,
                                AES_TAG_SIZE, state->tag) != 1)
        {
            return -1;
        }
    }
    else
    {
        if (EVP_CIPHER_CTX_reset(state->context) != 1 ||
            EVP_DecryptInit_ex(state->context, EVP_aes_256_gcm(),
                               NULL, state->key, state->nonce) != 1 ||
            EVP_DecryptUpdate(state->context, state->output,
                              &first_length, state->input,
                              state->input_length) != 1 ||
            EVP_CIPHER_CTX_ctrl(state->context,
                                EVP_CTRL_GCM_SET_TAG,
                                AES_TAG_SIZE, state->tag) != 1 ||
            EVP_DecryptFinal_ex(state->context,
                                state->output + first_length,
                                &final_length) != 1)
        {
            return -1;
        }
    }

    state->output_length = first_length + final_length;
    return 0;
}

static int run_aes_benchmarks(LARGE_INTEGER frequency)
{
    static const int message_sizes[] = {64, 1024, 16384};
    unsigned char plaintext[16384];
    unsigned char encrypted[16384];
    unsigned char decrypted[16384];
    AesState state;
    size_t size_index;
    int result = -1;

    memset(plaintext, 0x5A, sizeof(plaintext));
    memset(&state, 0, sizeof(state));
    state.context = EVP_CIPHER_CTX_new();
    state.input = plaintext;
    state.output = encrypted;

    if (state.context == NULL || RAND_bytes(state.key, sizeof(state.key)) != 1)
    {
        goto cleanup;
    }

    for (size_index = 0;
         size_index < sizeof(message_sizes) / sizeof(message_sizes[0]);
         ++size_index)
    {
        char label[64];
        int size = message_sizes[size_index];

        state.input = plaintext;
        state.output = encrypted;
        state.input_length = size;
        state.decrypt = 0;
        state.nonce_counter = 0;
        snprintf(label, sizeof(label), "AES-256-GCM encrypt %d B", size);

        if (measure(label, aes_operation, &state, frequency) != 0)
        {
            goto cleanup;
        }

        /* Prepare one valid ciphertext for the isolated decrypt benchmark. */
        state.input = plaintext;
        state.output = encrypted;
        state.input_length = size;
        state.decrypt = 0;
        state.nonce_counter = 0;
        if (aes_operation(&state) != 0)
        {
            goto cleanup;
        }

        state.input = encrypted;
        state.output = decrypted;
        state.input_length = size;
        state.decrypt = 1;
        snprintf(label, sizeof(label), "AES-256-GCM decrypt %d B", size);

        if (measure(label, aes_operation, &state, frequency) != 0)
        {
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    EVP_CIPHER_CTX_free(state.context);
    OPENSSL_cleanse(state.key, sizeof(state.key));
    OPENSSL_cleanse(state.tag, sizeof(state.tag));
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    OPENSSL_cleanse(encrypted, sizeof(encrypted));
    OPENSSL_cleanse(decrypted, sizeof(decrypted));
    return result;
}

static int run_cold_x25519_benchmark(void)
{
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER finish;
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;
    int result = EXIT_FAILURE;

    if (!QueryPerformanceFrequency(&frequency))
    {
        return EXIT_FAILURE;
    }

    QueryPerformanceCounter(&start);
    context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (context == NULL ||
        EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_keygen(context, &key) <= 0)
    {
        goto cleanup;
    }
    EVP_PKEY_CTX_free(context);
    context = NULL;
    QueryPerformanceCounter(&finish);

    printf("cold_x25519_keygen_ms,%.3f\n",
           qpc_seconds(start, finish, frequency) * 1000.0);
    result = EXIT_SUCCESS;

cleanup:
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(key);
    return result;
}

static int run_cold_hkdf_benchmark(void)
{
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER finish;
    HkdfState state;
    const unsigned char info[] =
        "HybridPQC-X25519-MLKEM768-AES256GCM";
    int result;

    memset(&state, 0, sizeof(state));
    memset(state.input, 0xA5, sizeof(state.input));
    memcpy(state.info, info, sizeof(info) - 1);
    state.info_length = sizeof(info) - 1;

    if (!QueryPerformanceFrequency(&frequency))
    {
        return EXIT_FAILURE;
    }

    QueryPerformanceCounter(&start);
    result = hkdf_full_helper(&state);
    QueryPerformanceCounter(&finish);

    if (result == 0)
    {
        printf("cold_hkdf_helper_ms,%.3f\n",
               qpc_seconds(start, finish, frequency) * 1000.0);
        result = EXIT_SUCCESS;
    }
    else
    {
        result = EXIT_FAILURE;
    }

    OPENSSL_cleanse(&state, sizeof(state));
    return result;
}

int main(int argc, char **argv)
{
    LARGE_INTEGER frequency;
    X25519State xstate;
    KemState kem_state;
    SignatureState sig_state;
    HkdfState hkdf_state;
    EVP_KDF *hkdf = NULL;
    unsigned char hkdf_input[64];
    unsigned char hkdf_info[] =
        "HybridPQC-X25519-MLKEM768-AES256GCM";
    OSSL_PARAM hkdf_params[5];
    const unsigned char message[] = "HybridPQC primitive benchmark";
    const char *kem_algorithm = OQS_KEM_alg_ml_kem_768;
    char kem_keygen_label[96];
    char kem_encaps_label[96];
    char kem_decaps_label[96];
    int result = EXIT_FAILURE;

    if (argc == 2 && strcmp(argv[1], "--cold-x25519") == 0)
    {
        return run_cold_x25519_benchmark();
    }
    if (argc == 2 && strcmp(argv[1], "--cold-hkdf") == 0)
    {
        return run_cold_hkdf_benchmark();
    }
    if (argc == 3 && strcmp(argv[1], "--kem") == 0)
    {
        if (strcmp(argv[2], "ml-kem-512") == 0)
        {
            kem_algorithm = OQS_KEM_alg_ml_kem_512;
        }
        else if (strcmp(argv[2], "ml-kem-768") == 0)
        {
            kem_algorithm = OQS_KEM_alg_ml_kem_768;
        }
        else if (strcmp(argv[2], "ml-kem-1024") == 0)
        {
            kem_algorithm = OQS_KEM_alg_ml_kem_1024;
        }
        else
        {
            fprintf(stderr,
                    "Unsupported ML-KEM profile '%s'. Choose "
                    "ml-kem-512, ml-kem-768, or ml-kem-1024.\n",
                    argv[2]);
            return EXIT_FAILURE;
        }
    }
    else if (argc != 1)
    {
        fprintf(stderr,
                "Usage: primitive_benchmark [--kem "
                "ml-kem-512|ml-kem-768|ml-kem-1024]\n");
        return EXIT_FAILURE;
    }

    memset(&xstate, 0, sizeof(xstate));
    memset(&kem_state, 0, sizeof(kem_state));
    memset(&sig_state, 0, sizeof(sig_state));
    memset(&hkdf_state, 0, sizeof(hkdf_state));
    memset(hkdf_input, 0xA5, sizeof(hkdf_input));

    if (!QueryPerformanceFrequency(&frequency))
    {
        fprintf(stderr, "High-resolution performance counter unavailable.\n");
        goto cleanup;
    }

    printf("# timer=QueryPerformanceCounter, warmup_batches=%d, "
           "measured_batches=%d, operations_per_batch=%d\n",
           WARMUP_BATCHES, MEASURED_BATCHES, OPERATIONS_PER_BATCH);
    printf("# selected_kem=%s\n", kem_algorithm);
    printf("operation,mean_us,min_batch_us,max_batch_us,stddev_us,operations\n");

    xstate.keygen_context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (xstate.keygen_context == NULL ||
        EVP_PKEY_keygen_init(xstate.keygen_context) <= 0 ||
        EVP_PKEY_keygen(xstate.keygen_context, &xstate.private_key) <= 0)
    {
        fprintf(stderr, "X25519 setup failed.\n");
        goto cleanup;
    }

    xstate.derive_context = EVP_PKEY_CTX_new(xstate.private_key, NULL);
    {
        EVP_PKEY_CTX *peer_context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        if (peer_context == NULL || EVP_PKEY_keygen_init(peer_context) <= 0 ||
            EVP_PKEY_keygen(peer_context, &xstate.peer_key) <= 0)
        {
            EVP_PKEY_CTX_free(peer_context);
            fprintf(stderr, "X25519 peer-key setup failed.\n");
            goto cleanup;
        }
        EVP_PKEY_CTX_free(peer_context);
    }

    {
        size_t peer_public_length = sizeof(xstate.peer_public);
        if (EVP_PKEY_get_raw_public_key(
                xstate.peer_key,
                xstate.peer_public,
                &peer_public_length) <= 0 ||
            peer_public_length != sizeof(xstate.peer_public))
        {
            fprintf(stderr, "X25519 peer public-key setup failed.\n");
            goto cleanup;
        }
    }

    if (xstate.derive_context == NULL ||
        measure("X25519 key generation (reused context)", x25519_keygen,
                &xstate, frequency) != 0 ||
        measure("X25519 key generation (fresh context)",
                x25519_keygen_fresh_context, &xstate, frequency) != 0 ||
        measure("X25519 shared-secret derivation (reused context)", x25519_derive,
                &xstate, frequency) != 0 ||
        measure("X25519 shared-secret derivation (fresh helper)",
                x25519_derive_fresh_context, &xstate, frequency) != 0)
    {
        goto cleanup;
    }

    kem_state.kem = OQS_KEM_new(kem_algorithm);
    if (kem_state.kem == NULL)
    {
        fprintf(stderr, "%s is unavailable in liboqs.\n", kem_algorithm);
        goto cleanup;
    }

    fprintf(stderr,
            "Selected KEM sizes: public_key=%zu, secret_key=%zu, "
            "ciphertext=%zu, shared_secret=%zu bytes\n",
            kem_state.kem->length_public_key,
            kem_state.kem->length_secret_key,
            kem_state.kem->length_ciphertext,
            kem_state.kem->length_shared_secret);

    snprintf(kem_keygen_label, sizeof(kem_keygen_label),
             "%s key generation", kem_state.kem->method_name);
    snprintf(kem_encaps_label, sizeof(kem_encaps_label),
             "%s encapsulation", kem_state.kem->method_name);
    snprintf(kem_decaps_label, sizeof(kem_decaps_label),
             "%s decapsulation", kem_state.kem->method_name);

    kem_state.public_key = malloc(kem_state.kem->length_public_key);
    kem_state.secret_key = malloc(kem_state.kem->length_secret_key);
    kem_state.ciphertext = malloc(kem_state.kem->length_ciphertext);
    kem_state.shared_secret = malloc(kem_state.kem->length_shared_secret);
    if (kem_state.public_key == NULL || kem_state.secret_key == NULL ||
        kem_state.ciphertext == NULL || kem_state.shared_secret == NULL ||
        measure(kem_keygen_label, kem_keygen,
                &kem_state, frequency) != 0 ||
        measure(kem_encaps_label, kem_encaps,
                &kem_state, frequency) != 0 ||
        measure(kem_decaps_label, kem_decaps,
                &kem_state, frequency) != 0)
    {
        goto cleanup;
    }

    sig_state.sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    sig_state.message = message;
    sig_state.message_length = sizeof(message) - 1;
    if (sig_state.sig == NULL)
    {
        fprintf(stderr, "ML-DSA-65 is unavailable in liboqs.\n");
        goto cleanup;
    }

    sig_state.public_key = malloc(sig_state.sig->length_public_key);
    sig_state.secret_key = malloc(sig_state.sig->length_secret_key);
    sig_state.signature = malloc(sig_state.sig->length_signature);
    if (sig_state.public_key == NULL || sig_state.secret_key == NULL ||
        sig_state.signature == NULL ||
        measure("ML-DSA-65 key generation", sig_keygen,
                &sig_state, frequency) != 0 ||
        measure("ML-DSA-65 signing", sig_sign,
                &sig_state, frequency) != 0 ||
        measure("ML-DSA-65 verification", sig_verify,
                &sig_state, frequency) != 0)
    {
        goto cleanup;
    }

    hkdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (hkdf == NULL)
    {
        fprintf(stderr, "Could not load HKDF.\n");
        goto cleanup;
    }
    hkdf_state.context = EVP_KDF_CTX_new(hkdf);
    hkdf_params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_MODE, "EXTRACT_AND_EXPAND", 0);
    hkdf_params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, "SHA384", 0);
    memcpy(hkdf_state.input, hkdf_input, sizeof(hkdf_input));
    memcpy(hkdf_state.info, hkdf_info, sizeof(hkdf_info) - 1);
    hkdf_state.info_length = sizeof(hkdf_info) - 1;
    hkdf_params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, hkdf_state.input, sizeof(hkdf_state.input));
    hkdf_params[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, hkdf_state.info, hkdf_state.info_length);
    hkdf_params[4] = OSSL_PARAM_construct_end();
    hkdf_state.params = hkdf_params;
    if (hkdf_state.context == NULL ||
        measure("HKDF-SHA-384 (reused context)", hkdf_derive,
                &hkdf_state, frequency) != 0 ||
        measure("HKDF-SHA-384 (fresh helper)", hkdf_full_helper,
                &hkdf_state, frequency) != 0 ||
        run_aes_benchmarks(frequency) != 0)
    {
        goto cleanup;
    }

    result = EXIT_SUCCESS;

cleanup:
    EVP_PKEY_CTX_free(xstate.keygen_context);
    EVP_PKEY_CTX_free(xstate.derive_context);
    EVP_PKEY_free(xstate.private_key);
    EVP_PKEY_free(xstate.peer_key);
    OQS_KEM_free(kem_state.kem);
    OQS_SIG_free(sig_state.sig);
    EVP_KDF_CTX_free(hkdf_state.context);
    EVP_KDF_free(hkdf);
    free(kem_state.public_key);
    free(kem_state.secret_key);
    free(kem_state.ciphertext);
    free(kem_state.shared_secret);
    free(sig_state.public_key);
    free(sig_state.secret_key);
    free(sig_state.signature);
    OPENSSL_cleanse(hkdf_input, sizeof(hkdf_input));
    OPENSSL_cleanse(hkdf_state.input, sizeof(hkdf_state.input));
    OPENSSL_cleanse(hkdf_state.info, sizeof(hkdf_state.info));
    OPENSSL_cleanse(hkdf_state.output, sizeof(hkdf_state.output));
    return result;
}
