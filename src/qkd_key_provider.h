#ifndef QKD_KEY_PROVIDER_H
#define QKD_KEY_PROVIDER_H

#include <stddef.h>

#define QKD_KEY_BYTES 32
#define QKD_KEY_ID_BYTES 64

typedef struct {
    int key_consumed;
} qkd_simulator_pool;

typedef enum {
    QKD_PROVIDER_OK = 0,
    QKD_PROVIDER_UNAVAILABLE = 1,
    QKD_PROVIDER_INVALID_ARGUMENT = 2,
    QKD_PROVIDER_REUSED = 3
} qkd_provider_status;

/*
 * Obtain one already-shared key from a QKD key manager.
 * key_id is an opaque identifier; key bytes must never be logged.
 * The simulator is for protocol plumbing and demonstrations only.
 */
/* Initialize a local key-pool handle before requesting keys from it. */
void qkd_simulator_pool_init(qkd_simulator_pool *pool);

qkd_provider_status qkd_simulator_get_key(
    qkd_simulator_pool *pool,
    const char *key_id,
    unsigned char *key_out,
    size_t key_out_capacity,
    size_t *key_out_length);

/* Combine classical, post-quantum, and QKD inputs into an AES-256 key. */
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
    size_t session_key_capacity);

#endif
