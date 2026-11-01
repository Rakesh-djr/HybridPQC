#include "qkd_key_provider.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#define AES_256_KEY_BYTES 32
#define HKDF_SALT_BYTES 32

static const unsigned char simulator_fixture[QKD_KEY_BYTES] = {
    0x51, 0x4b, 0x44, 0x2d, 0x53, 0x49, 0x4d, 0x55,
    0x4c, 0x41, 0x54, 0x4f, 0x52, 0x2d, 0x4f, 0x4e,
    0x4c, 0x59, 0x2d, 0x4e, 0x4f, 0x54, 0x2d, 0x52,
    0x45, 0x41, 0x4c, 0x2d, 0x51, 0x4b, 0x44, 0x21
};

void qkd_simulator_pool_init(qkd_simulator_pool *pool)
{
    if (pool != NULL) {
        pool->key_consumed = 0;
    }
}

qkd_provider_status qkd_simulator_get_key(
    qkd_simulator_pool *pool,
    const char *key_id,
    unsigned char *key_out,
    size_t key_out_capacity,
    size_t *key_out_length)
{
    if (pool == NULL || key_id == NULL || key_out == NULL || key_out_length == NULL ||
        key_out_capacity < QKD_KEY_BYTES) {
        return QKD_PROVIDER_INVALID_ARGUMENT;
    }

    *key_out_length = 0;
    if (getenv("PHASE8_SIMULATOR_EMPTY") != NULL &&
        strcmp(getenv("PHASE8_SIMULATOR_EMPTY"), "1") == 0) {
        return QKD_PROVIDER_UNAVAILABLE;
    }
    if (pool->key_consumed) {
        return QKD_PROVIDER_REUSED;
    }
    if (strcmp(key_id, "phase8-demo-key-001") != 0) {
        return QKD_PROVIDER_UNAVAILABLE;
    }

    memcpy(key_out, simulator_fixture, sizeof(simulator_fixture));
    *key_out_length = sizeof(simulator_fixture);
    pool->key_consumed = 1;
    return QKD_PROVIDER_OK;
}

static void store_u32_be(unsigned char output[4], uint32_t value)
{
    output[0] = (unsigned char)(value >> 24);
    output[1] = (unsigned char)(value >> 16);
    output[2] = (unsigned char)(value >> 8);
    output[3] = (unsigned char)value;
}

int qkd_derive_hybrid_key(
    const unsigned char *x25519_secret,
    size_t x25519_secret_length,
    const unsigned char *mlkem_secret,
    size_t mlkem_secret_length,
    const unsigned char *qkd_secret,
    size_t qkd_secret_length,
    const unsigned char *transcript_hash,
    size_t transcript_hash_length,
    unsigned char *session_key_out,
    size_t session_key_capacity)
{
    static const unsigned char salt[HKDF_SALT_BYTES] = { 0 };
    static const char info[] =
        "HybridPQC-X25519-MLKEM-QKD-AES256GCM-v1";
    unsigned char ikm[4 * (4 + 1024)];
    size_t ikm_length = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[5];
    int param_index = 0;
    int result = 0;

    if (x25519_secret == NULL || mlkem_secret == NULL || qkd_secret == NULL ||
        transcript_hash == NULL || session_key_out == NULL ||
        x25519_secret_length == 0 || mlkem_secret_length == 0 ||
        qkd_secret_length == 0 || transcript_hash_length == 0 ||
        x25519_secret_length > 1024 || mlkem_secret_length > 1024 ||
        qkd_secret_length > 1024 || transcript_hash_length > 1024 ||
        session_key_capacity < AES_256_KEY_BYTES) {
        return 0;
    }

    const unsigned char *components[] = {
        x25519_secret, mlkem_secret, qkd_secret, transcript_hash
    };
    const size_t lengths[] = {
        x25519_secret_length, mlkem_secret_length,
        qkd_secret_length, transcript_hash_length
    };

    for (size_t i = 0; i < 4; ++i) {
        unsigned char encoded_length[4];
        if (lengths[i] > UINT32_MAX || ikm_length + 4 + lengths[i] > sizeof(ikm)) {
            goto cleanup;
        }
        store_u32_be(encoded_length, (uint32_t)lengths[i]);
        memcpy(ikm + ikm_length, encoded_length, sizeof(encoded_length));
        ikm_length += sizeof(encoded_length);
        memcpy(ikm + ikm_length, components[i], lengths[i]);
        ikm_length += lengths[i];
    }

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        goto cleanup;
    }
    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL) {
        goto cleanup;
    }

    params[param_index++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, (char *)"SHA384", 0);
    params[param_index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, ikm, ikm_length);
    params[param_index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, (void *)salt, sizeof(salt));
    params[param_index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, (void *)info, sizeof(info) - 1);
    params[param_index] = OSSL_PARAM_construct_end();

    result = EVP_KDF_derive(ctx, session_key_out, AES_256_KEY_BYTES, params) > 0;

cleanup:
    OPENSSL_cleanse(ikm, sizeof(ikm));
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return result;
}
