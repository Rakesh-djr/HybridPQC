#include "qkd_key_provider.h"

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>

#define COMPONENT_BYTES 32
#define SESSION_KEY_BYTES 32

int main(void)
{
    const unsigned char x25519_secret[COMPONENT_BYTES] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    const unsigned char mlkem_secret[COMPONENT_BYTES] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
    };
    static const unsigned char transcript[] =
        "phase8-demo-authenticated-transcript";
    unsigned char transcript_hash[SHA384_DIGEST_LENGTH];
    unsigned char client_qkd[QKD_KEY_BYTES];
    unsigned char server_qkd[QKD_KEY_BYTES];
    unsigned char client_key[SESSION_KEY_BYTES];
    unsigned char server_key[SESSION_KEY_BYTES];
    unsigned char unavailable_key[QKD_KEY_BYTES];
    qkd_simulator_pool client_pool;
    qkd_simulator_pool server_pool;
    qkd_simulator_pool missing_pool;
    size_t client_qkd_length = 0;
    size_t server_qkd_length = 0;
    size_t unavailable_key_length = 99;

    qkd_simulator_pool_init(&client_pool);
    qkd_simulator_pool_init(&server_pool);
    qkd_simulator_pool_init(&missing_pool);
    SHA384(transcript, sizeof(transcript) - 1, transcript_hash);
    if (qkd_simulator_get_key(&client_pool, "phase8-demo-key-001", client_qkd,
                              sizeof(client_qkd), &client_qkd_length) !=
            QKD_PROVIDER_OK ||
        qkd_simulator_get_key(&server_pool, "phase8-demo-key-001", server_qkd,
                              sizeof(server_qkd), &server_qkd_length) !=
            QKD_PROVIDER_OK) {
        fprintf(stderr, "QKD key source unavailable; refusing QKD-mode session.\n");
        return 1;
    }

    if (client_qkd_length != server_qkd_length ||
        CRYPTO_memcmp(client_qkd, server_qkd, client_qkd_length) != 0) {
        fprintf(stderr, "QKD endpoints did not obtain matching key material.\n");
        return 1;
    }

    if (qkd_simulator_get_key(&missing_pool, "missing-key-id", unavailable_key,
                              sizeof(unavailable_key),
                              &unavailable_key_length) !=
            QKD_PROVIDER_UNAVAILABLE || unavailable_key_length != 0) {
        fprintf(stderr, "Unavailable-key case did not fail closed.\n");
        return 1;
    }
    puts("[PASS] unavailable QKD key ID fails closed");

    if (qkd_simulator_get_key(&client_pool, "phase8-demo-key-001",
                              unavailable_key, sizeof(unavailable_key),
                              &unavailable_key_length) != QKD_PROVIDER_REUSED ||
        unavailable_key_length != 0) {
        fprintf(stderr, "Repeated QKD key ID was not rejected.\n");
        return 1;
    }
    puts("[PASS] consumed QKD key ID cannot be reused");

    if (!qkd_derive_hybrid_key(
            x25519_secret, sizeof(x25519_secret),
            mlkem_secret, sizeof(mlkem_secret),
            client_qkd, client_qkd_length,
            transcript_hash, sizeof(transcript_hash),
            client_key, sizeof(client_key)) ||
        !qkd_derive_hybrid_key(
            x25519_secret, sizeof(x25519_secret),
            mlkem_secret, sizeof(mlkem_secret),
            server_qkd, server_qkd_length,
            transcript_hash, sizeof(transcript_hash),
            server_key, sizeof(server_key))) {
        fprintf(stderr, "Hybrid HKDF derivation failed.\n");
        return 1;
    }

    if (CRYPTO_memcmp(client_key, server_key, sizeof(client_key)) != 0) {
        fprintf(stderr, "Endpoints derived different session keys.\n");
        return 1;
    }

    server_qkd[0] ^= 0x01;
    if (!qkd_derive_hybrid_key(
            x25519_secret, sizeof(x25519_secret),
            mlkem_secret, sizeof(mlkem_secret),
            server_qkd, server_qkd_length,
            transcript_hash, sizeof(transcript_hash),
            server_key, sizeof(server_key)) ||
        CRYPTO_memcmp(client_key, server_key, sizeof(client_key)) == 0) {
        fprintf(stderr, "Mismatched QKD keys were not detected by key agreement.\n");
        return 1;
    }
    puts("[PASS] mismatched QKD keys produce different session keys");

    puts("PHASE 8 QKD ABSTRACTION DEMO: PASS");
    puts("Classical + ML-KEM + simulated shared QKD input -> HKDF-SHA-384 -> AES-256 key");
    puts("QKD mode uses a fixed simulator fixture; this is not real QKD security or a live channel.");

    OPENSSL_cleanse(client_qkd, sizeof(client_qkd));
    OPENSSL_cleanse(server_qkd, sizeof(server_qkd));
    OPENSSL_cleanse(client_key, sizeof(client_key));
    OPENSSL_cleanse(server_key, sizeof(server_key));
    OPENSSL_cleanse(unavailable_key, sizeof(unavailable_key));
    OPENSSL_cleanse(transcript_hash, sizeof(transcript_hash));
    return 0;
}
