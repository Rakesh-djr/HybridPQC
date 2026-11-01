#define _CRT_SECURE_NO_WARNINGS

#include "protocol_auth.h"
#include "crypto_policy.h"
#ifdef PHASE8_QKD_SIMULATOR
#include "qkd_key_provider.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>

#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

/* ============================================================
   Configuration
   ============================================================ */

#ifndef SERVER_PORT
#define SERVER_PORT 5555
#endif

#define SERVER_MLDSA_SECRET_KEY_FILE \
    "C:\\HybridPQC\\keys\\server_mldsa_secret.key"

/* ============================================================
   Utility
   ============================================================ */

static void print_openssl_error(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
}


/* ============================================================
   Load Binary File
   ============================================================ */

static int load_binary_file(
    const char *filename,
    unsigned char *buffer,
    size_t expected_size)
{
    FILE *file;
    long file_size;

    file = fopen(filename, "rb");

    if (file == NULL)
    {
        fprintf(
            stderr,
            "Failed to open key file: %s\n",
            filename
        );

        return -1;
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return -1;
    }

    file_size = ftell(file);

    if (file_size < 0)
    {
        fclose(file);
        return -1;
    }

    if ((size_t)file_size != expected_size)
    {
        fprintf(
            stderr,
            "Invalid key file size: %ld bytes, expected %zu bytes\n",
            file_size,
            expected_size
        );

        fclose(file);
        return -1;
    }

    rewind(file);

    if (fread(buffer, 1, expected_size, file) != expected_size)
    {
        fprintf(stderr, "Failed to read key file\n");
        fclose(file);
        return -1;
    }

    fclose(file);

    return 0;
}


/* ============================================================
   X25519 Key Generation
   ============================================================ */

static EVP_PKEY *generate_x25519_keypair(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *keypair = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (ctx == NULL)
    {
        print_openssl_error("Failed to create X25519 context");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        print_openssl_error("X25519 key generation initialization failed");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &keypair) <= 0)
    {
        print_openssl_error("X25519 key generation failed");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    return keypair;
}


/* ============================================================
   X25519 Shared Secret
   ============================================================ */

static int derive_x25519_shared_secret(
    EVP_PKEY *private_key,
    const unsigned char *peer_public_key,
    unsigned char *shared_secret)
{
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t shared_secret_len = 32;
    int result = -1;

    peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        NULL,
        peer_public_key,
        X25519_PUBLIC_KEY_SIZE
    );

    if (peer_key == NULL)
    {
        print_openssl_error(
            "Failed to create peer X25519 public key"
        );

        return -1;
    }

    ctx = EVP_PKEY_CTX_new(private_key, NULL);

    if (ctx == NULL)
    {
        print_openssl_error(
            "Failed to create X25519 derive context"
        );

        EVP_PKEY_free(peer_key);
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        print_openssl_error(
            "X25519 derive initialization failed"
        );

        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
    {
        print_openssl_error(
            "Failed to set X25519 peer"
        );

        goto cleanup;
    }

    if (EVP_PKEY_derive(
            ctx,
            shared_secret,
            &shared_secret_len) <= 0)
    {
        print_openssl_error(
            "X25519 shared secret derivation failed"
        );

        goto cleanup;
    }

    if (shared_secret_len != 32)
    {
        fprintf(
            stderr,
            "Unexpected X25519 shared secret size\n"
        );

        goto cleanup;
    }

    result = 0;

cleanup:

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);

    return result;
}


/* ============================================================
   HKDF-SHA-384
   ============================================================ */

static int derive_hybrid_session_key(
    const unsigned char *x25519_secret,
    const unsigned char *mlkem_secret,
    uint8_t kem_profile_id,
#ifdef PHASE8_QKD_SIMULATOR
    const unsigned char *transcript,
    size_t transcript_length,
#endif
    unsigned char *session_key)
{
#ifdef PHASE8_QKD_SIMULATOR
    static qkd_simulator_pool provider_pool = {0};
    unsigned char qkd_secret[QKD_KEY_BYTES] = {0};
    unsigned char transcript_hash[48] = {0};
    unsigned int transcript_hash_length = 0;
    size_t qkd_secret_length = 0;
    int result = -1;
    LARGE_INTEGER provider_start, provider_finish;
    LARGE_INTEGER combine_start, combine_finish;
    LARGE_INTEGER phase8_frequency;

    (void)kem_profile_id;
    QueryPerformanceFrequency(&phase8_frequency);
    QueryPerformanceCounter(&provider_start);
    qkd_provider_status provider_status = qkd_simulator_get_key(
        &provider_pool, "phase8-demo-key-001", qkd_secret,
        sizeof(qkd_secret), &qkd_secret_length);
    QueryPerformanceCounter(&provider_finish);
    printf("[PHASE8_METRIC] provider_lookup_ms: %.6f\n",
           (double)(provider_finish.QuadPart - provider_start.QuadPart) *
               1000.0 / (double)phase8_frequency.QuadPart);
    if (provider_status != QKD_PROVIDER_OK) {
        fprintf(stderr, "[PHASE8] QKD provider failed closed (status %d)\n",
                (int)provider_status);
        goto qkd_cleanup;
    }
    if (EVP_Digest(transcript, transcript_length, transcript_hash,
                   &transcript_hash_length, EVP_sha384(), NULL) != 1 ||
        transcript_hash_length != sizeof(transcript_hash)) {
        fprintf(stderr, "[PHASE8] transcript hashing failed\n");
        goto qkd_cleanup;
    }

    QueryPerformanceCounter(&combine_start);
    result = qkd_derive_hybrid_key(
        x25519_secret, 32, mlkem_secret, 32,
        qkd_secret, qkd_secret_length,
        transcript_hash, transcript_hash_length,
        session_key, 32) ? 0 : -1;
    QueryPerformanceCounter(&combine_finish);
    printf("[PHASE8_METRIC] qkd_hkdf_combine_ms: %.6f\n",
           (double)(combine_finish.QuadPart - combine_start.QuadPart) *
               1000.0 / (double)phase8_frequency.QuadPart);
    if (result == 0) {
        printf("[PHASE8] QKD simulator key combined with X25519 + ML-KEM; not real QKD\n");
    }

qkd_cleanup:
    OPENSSL_cleanse(qkd_secret, sizeof(qkd_secret));
    OPENSSL_cleanse(transcript_hash, sizeof(transcript_hash));
    return result;
#else
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;

    unsigned char combined_secret[64];

    const char *digest = "SHA384";

    static const unsigned char info_prefix[] =
        "HybridPQC-X25519-ML-KEM-AES256GCM-v2";
    unsigned char info[sizeof(info_prefix)];

    OSSL_PARAM params[5];

    int result = -1;

    memcpy(
        combined_secret,
        x25519_secret,
        32
    );

    memcpy(
        combined_secret + 32,
        mlkem_secret,
        32
    );
    memcpy(info, info_prefix, sizeof(info_prefix) - 1);
    info[sizeof(info_prefix) - 1] = kem_profile_id;

    kdf = EVP_KDF_fetch(
        NULL,
        "HKDF",
        NULL
    );

    if (kdf == NULL)
    {
        print_openssl_error(
            "Failed to fetch HKDF"
        );

        goto cleanup;
    }

    kdf_ctx = EVP_KDF_CTX_new(kdf);

    if (kdf_ctx == NULL)
    {
        print_openssl_error(
            "Failed to create HKDF context"
        );

        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_MODE,
        "EXTRACT_AND_EXPAND",
        0
    );

    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST,
        (char *)digest,
        0
    );

    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY,
        combined_secret,
        sizeof(combined_secret)
    );

    params[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO,
        info,
        sizeof(info)
    );

    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(
            kdf_ctx,
            session_key,
            32,
            params) <= 0)
    {
        print_openssl_error(
            "HKDF derivation failed"
        );

        goto cleanup;
    }

    result = 0;

cleanup:

    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);

    OPENSSL_cleanse(
        combined_secret,
        sizeof(combined_secret)
    );

    return result;
#endif
}


/* ============================================================
   Replay Protection Helpers
   ============================================================ */

static uint64_t decode_u64_be(
    const unsigned char in[8])
{
    uint64_t value = 0;
    int i;

    for (i = 0; i < 8; i++)
    {
        value =
            (value << 8) |
            (uint64_t)in[i];
    }

    return value;
}


/* ============================================================
   AES-256-GCM Decryption with AAD
   ============================================================ */

static int aes_gcm_decrypt(
    const unsigned char *key,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *nonce,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char *tag,
    unsigned char *plaintext,
    size_t *plaintext_len)
{
    EVP_CIPHER_CTX *ctx = NULL;

    int len = 0;
    int final_len = 0;

    int result = -1;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
    {
        print_openssl_error(
            "Failed to create AES-GCM context"
        );

        return -1;
    }

    if (EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1)
    {
        print_openssl_error(
            "AES-GCM initialization failed"
        );

        goto cleanup;
    }

    if (EVP_DecryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce) != 1)
    {
        print_openssl_error(
            "AES-GCM key/nonce initialization failed"
        );

        goto cleanup;
    }

    /* Authenticate the sequence number as AES-GCM AAD. */
    if (EVP_DecryptUpdate(
            ctx,
            NULL,
            &len,
            aad,
            (int)aad_len) != 1)
    {
        print_openssl_error(
            "AES-GCM AAD processing failed"
        );

        goto cleanup;
    }

    if (EVP_DecryptUpdate(
            ctx,
            plaintext,
            &len,
            ciphertext,
            (int)ciphertext_len) != 1)
    {
        print_openssl_error(
            "AES-GCM decryption failed"
        );

        goto cleanup;
    }

    *plaintext_len = (size_t)len;

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            GCM_TAG_SIZE,
            (void *)tag) != 1)
    {
        print_openssl_error(
            "Failed to set GCM authentication tag"
        );

        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext + len,
            &final_len) != 1)
    {
        fprintf(
            stderr,
            "AES-GCM authentication FAILED\n"
        );

        goto cleanup;
    }

    *plaintext_len += (size_t)final_len;

    result = 0;

cleanup:

    EVP_CIPHER_CTX_free(ctx);

    return result;
}

/* ============================================================
   Build Authentication Transcript
   ============================================================ */

static int build_auth_transcript(
    const unsigned char *client_x25519_public,
    unsigned char kem_profile_id,
    const unsigned char *client_mlkem_public,
    size_t client_mlkem_public_len,
    const unsigned char *server_x25519_public,
    const unsigned char *server_mlkem_ciphertext,
    size_t server_mlkem_ciphertext_len,
    unsigned char *transcript,
    size_t *transcript_len)
{
    size_t offset = 0;

    /*
     * Domain separator
     */

    memcpy(
        transcript + offset,
        AUTH_DOMAIN_SEPARATOR,
        AUTH_DOMAIN_SEPARATOR_SIZE
    );

    offset += AUTH_DOMAIN_SEPARATOR_SIZE;

    /*
     * Protocol version
     */

    transcript[offset++] =
        HYBRID_AUTH_PROTOCOL_VERSION;

    /*
     * Authentication algorithm
     */

    transcript[offset++] =
        AUTH_ALG_MLDSA65;

    transcript[offset++] = kem_profile_id;

    /*
     * Alice X25519 public key
     */

    memcpy(
        transcript + offset,
        client_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    offset += X25519_PUBLIC_KEY_SIZE;

    /*
     * Alice ML-KEM public key
     */

    memcpy(
        transcript + offset,
        client_mlkem_public,
        client_mlkem_public_len
    );

    offset += client_mlkem_public_len;

    /*
     * Bob X25519 public key
     */

    memcpy(
        transcript + offset,
        server_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    offset += X25519_PUBLIC_KEY_SIZE;

    /*
     * Bob's ML-KEM ciphertext
     */

    memcpy(
        transcript + offset,
        server_mlkem_ciphertext,
        server_mlkem_ciphertext_len
    );

    offset += server_mlkem_ciphertext_len;

    *transcript_len = offset;

    return 0;
}

static const char *kem_algorithm_for_profile(uint8_t profile_id)
{
    switch (profile_id)
    {
        case 1: return OQS_KEM_alg_ml_kem_512;
        case 2: return OQS_KEM_alg_ml_kem_768;
        case 3: return OQS_KEM_alg_ml_kem_1024;
        default: return NULL;
    }
}

static int parse_profile_id(const char *value, uint8_t *profile_id)
{
    if (strcmp(value, "512") == 0) *profile_id = 1;
    else if (strcmp(value, "768") == 0) *profile_id = 2;
    else if (strcmp(value, "1024") == 0) *profile_id = 3;
    else return -1;
    return 0;
}


/* ============================================================
   Create Listening Socket
   ============================================================ */

static SOCKET create_server_socket(void)
{
    SOCKET server_socket = INVALID_SOCKET;

    struct sockaddr_in server_address;

    int reuse = 1;

    server_socket = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP
    );

    if (server_socket == INVALID_SOCKET)
    {
        fprintf(
            stderr,
            "Failed to create server socket\n"
        );

        return INVALID_SOCKET;
    }

    setsockopt(
        server_socket,
        SOL_SOCKET,
        SO_REUSEADDR,
        (const char *)&reuse,
        sizeof(reuse)
    );

    memset(
        &server_address,
        0,
        sizeof(server_address)
    );

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(
            server_socket,
            (struct sockaddr *)&server_address,
            sizeof(server_address)) == SOCKET_ERROR)
    {
        fprintf(
            stderr,
            "Failed to bind server socket\n"
        );

        closesocket(server_socket);

        return INVALID_SOCKET;
    }

    if (listen(server_socket, 1) == SOCKET_ERROR)
    {
        fprintf(
            stderr,
            "Failed to listen on port %d\n",
            SERVER_PORT
        );

        closesocket(server_socket);

        return INVALID_SOCKET;
    }

    return server_socket;
}


/* ============================================================
   Main
   ============================================================ */

int main(int argc, char **argv)
{
    WSADATA wsa_data;

    SOCKET server_socket = INVALID_SOCKET;
    SOCKET client_socket = INVALID_SOCKET;

    struct sockaddr_in client_address;
    int client_address_length =
        sizeof(client_address);

    OQS_SIG *sig = NULL;
    OQS_KEM *kem = NULL;

    unsigned char *mldsa_secret_key = NULL;

    unsigned char client_hello[
        CLIENT_HELLO_SIZE
    ];

    unsigned char client_x25519_public[
        X25519_PUBLIC_KEY_SIZE
    ];

    unsigned char client_mlkem_public[
        MLKEM_PUBLIC_KEY_SIZE
    ];

    unsigned char server_x25519_public[
        X25519_PUBLIC_KEY_SIZE
    ];

    unsigned char server_mlkem_ciphertext[
        MLKEM_CIPHERTEXT_SIZE
    ];

    unsigned char mlkem_shared_secret[
        32
    ];

    unsigned char x25519_shared_secret[
        32
    ];

    unsigned char hybrid_session_key[
        32
    ];

    unsigned char transcript[
        AUTH_TRANSCRIPT_SIZE
    ];

    size_t transcript_len = 0;

    unsigned char signature[
        MLDSA65_SIGNATURE_SIZE
    ];

    size_t signature_len = 0;

    unsigned char server_hello[
        SERVER_HELLO_AUTH_SIZE
    ];

    size_t server_hello_offset = 0;

    unsigned char *encrypted_payload = NULL;

    uint32_t encrypted_payload_len = 0;
    size_t client_hello_len = 0;

    uint8_t packet_type = 0;

    unsigned char plaintext[
        MAX_MESSAGE_SIZE
    ];

    size_t plaintext_len = 0;

    EVP_PKEY *server_x25519_key = NULL;

    OQS_STATUS oqs_status;

    int result = EXIT_FAILURE;

    uint64_t expected_sequence = 0;
    ULONG64 cpu_cycles_accept_start = 0;
    ULONG64 cpu_cycles_key_ready = 0;
    LARGE_INTEGER timer_frequency;
    LARGE_INTEGER stage_start;
    LARGE_INTEGER stage_finish;
    uint8_t minimum_profile_id = PHASE6_KEM_PROFILE_ID;
    size_t kem_public_key_len = 0;
    size_t kem_ciphertext_len = 0;
    size_t expected_server_hello_len = 0;

#if defined(PHASE6_KEM_ADAPTIVE)
    minimum_profile_id = 2;
    if (argc == 3 && strcmp(argv[1], "--minimum") == 0)
    {
        if (parse_profile_id(argv[2], &minimum_profile_id) != 0)
        {
            fprintf(stderr, "Minimum profile must be 512, 768, or 1024.\n");
            return EXIT_FAILURE;
        }
    }
    else if (argc != 1)
    {
        fprintf(stderr, "Usage: server_auth_phase6_adaptive.exe [--minimum 512|768|1024]\n");
        return EXIT_FAILURE;
    }
#else
    (void)argc;
    (void)argv;
#endif


    /* ========================================================
       Initialize Winsock
       ======================================================== */

    if (WSAStartup(
            MAKEWORD(2, 2),
            &wsa_data) != 0)
    {
        fprintf(
            stderr,
            "WSAStartup failed\n"
        );

        return EXIT_FAILURE;
    }

    if (!QueryPerformanceFrequency(&timer_frequency))
    {
        fprintf(stderr, "High-resolution performance counter unavailable\n");
        WSACleanup();
        return EXIT_FAILURE;
    }


    printf("\n");
    printf("===============================================\n");
    printf("   AUTHENTICATED HYBRID PQC SERVER\n");
    printf("===============================================\n");
    printf("\n");


    /* ========================================================
       Initialize ML-DSA
       ======================================================== */

    sig = OQS_SIG_new(
        OQS_SIG_alg_ml_dsa_65
    );

    if (sig == NULL)
    {
        fprintf(
            stderr,
            "Failed to initialize ML-DSA-65\n"
        );

        goto cleanup;
    }

    if (sig->length_secret_key !=
        MLDSA65_SECRET_KEY_SIZE)
    {
        fprintf(
            stderr,
            "Unexpected ML-DSA secret key size\n"
        );

        goto cleanup;
    }

    if (sig->length_signature !=
        MLDSA65_SIGNATURE_SIZE)
    {
        fprintf(
            stderr,
            "Unexpected ML-DSA signature size\n"
        );

        goto cleanup;
    }


    /* ========================================================
       Load Persistent Bob Identity
       ======================================================== */

    mldsa_secret_key =
        (unsigned char *)malloc(
            MLDSA65_SECRET_KEY_SIZE
        );

    if (mldsa_secret_key == NULL)
    {
        fprintf(
            stderr,
            "Failed to allocate ML-DSA secret key\n"
        );

        goto cleanup;
    }

    if (load_binary_file(
            SERVER_MLDSA_SECRET_KEY_FILE,
            mldsa_secret_key,
            MLDSA65_SECRET_KEY_SIZE) != 0)
    {
        goto cleanup;
    }

    printf(
        "[+] Bob ML-DSA-65 identity loaded\n"
    );

#ifdef PHASE5_PREWARM_CRYPTO
    {
        unsigned char warm_secret_a[32] = {0};
        unsigned char warm_secret_b[32] = {0};
        unsigned char warm_key[32];
        EVP_PKEY *warm_x25519_key = generate_x25519_keypair();

        if (warm_x25519_key == NULL ||
            derive_hybrid_session_key(
                warm_secret_a,
                warm_secret_b,
                PHASE6_KEM_PROFILE_ID,
                warm_key) != 0)
        {
            EVP_PKEY_free(warm_x25519_key);
            OPENSSL_cleanse(warm_secret_a, sizeof(warm_secret_a));
            OPENSSL_cleanse(warm_secret_b, sizeof(warm_secret_b));
            OPENSSL_cleanse(warm_key, sizeof(warm_key));
            goto cleanup;
        }

        EVP_PKEY_free(warm_x25519_key);
        OPENSSL_cleanse(warm_secret_a, sizeof(warm_secret_a));
        OPENSSL_cleanse(warm_secret_b, sizeof(warm_secret_b));
        OPENSSL_cleanse(warm_key, sizeof(warm_key));
        printf("[PHASE5] OpenSSL X25519 and HKDF initialized before listening\n");
    }
#endif


    /* ========================================================
       Create TCP Server
       ======================================================== */

    server_socket = create_server_socket();

    if (server_socket == INVALID_SOCKET)
    {
        goto cleanup;
    }

    printf(
        "[+] Server listening on TCP port %d\n",
        SERVER_PORT
    );

    printf(
        "[+] Waiting for Alice...\n"
    );


    /* ========================================================
       Accept Alice
       ======================================================== */

    if (!QueryThreadCycleTime(
            GetCurrentThread(),
            &cpu_cycles_accept_start))
    {
        fprintf(stderr, "Could not read server CPU cycle counter\n");
        goto cleanup;
    }

    client_socket = accept(
        server_socket,
        (struct sockaddr *)&client_address,
        &client_address_length
    );

    if (client_socket == INVALID_SOCKET)
    {
        fprintf(
            stderr,
            "Failed to accept client\n"
        );

        goto cleanup;
    }

    printf(
        "[+] Alice connected\n"
    );


    /* ========================================================
       Receive CLIENT_HELLO
       ======================================================== */

    QueryPerformanceCounter(&stage_start);
    if (recv_auth_packet(
            client_socket,
            &packet_type,
            &encrypted_payload,
            &encrypted_payload_len) != 0)
    {
        fprintf(
            stderr,
            "Failed to receive CLIENT_HELLO\n"
        );

        goto cleanup;
    }
    QueryPerformanceCounter(&stage_finish);
    printf("[PHASE5_STAGE] Receive CLIENT_HELLO: %.3f ms\n",
           (double)(stage_finish.QuadPart - stage_start.QuadPart) *
               1000.0 / (double)timer_frequency.QuadPart);

    if (packet_type != PACKET_CLIENT_HELLO)
    {
        fprintf(
            stderr,
            "Expected CLIENT_HELLO, received packet type %u\n",
            packet_type
        );

        goto cleanup;
    }

    if (encrypted_payload_len > sizeof(client_hello))
    {
        fprintf(
            stderr,
            "Invalid CLIENT_HELLO size\n"
        );

        goto cleanup;
    }

    memcpy(
        client_hello,
        encrypted_payload,
        encrypted_payload_len
    );
    client_hello_len = encrypted_payload_len;

    free(encrypted_payload);
    encrypted_payload = NULL;

    encrypted_payload_len = 0;


    /* ========================================================
       Parse Alice's Public Keys
       ======================================================== */

    memcpy(
        client_x25519_public,
        client_hello,
        X25519_PUBLIC_KEY_SIZE
    );

    uint8_t client_kem_profile_id =
        client_hello[X25519_PUBLIC_KEY_SIZE];
    if (client_kem_profile_id < minimum_profile_id ||
        kem_algorithm_for_profile(client_kem_profile_id) == NULL)
    {
        fprintf(stderr, "Client selected ML-KEM profile %u below server policy or unsupported.\n",
                client_kem_profile_id);
        goto cleanup;
    }

#if !defined(PHASE6_KEM_ADAPTIVE)
    if (client_kem_profile_id != PHASE6_KEM_PROFILE_ID)
    {
        fprintf(stderr, "Client requested a profile different from this server build.\n");
        goto cleanup;
    }
#endif

    kem = OQS_KEM_new(kem_algorithm_for_profile(client_kem_profile_id));
    if (kem == NULL)
    {
        fprintf(stderr, "Failed to initialize the requested ML-KEM profile.\n");
        goto cleanup;
    }
    kem_public_key_len = kem->length_public_key;
    kem_ciphertext_len = kem->length_ciphertext;
    if (client_hello_len !=
        X25519_PUBLIC_KEY_SIZE + 1 + kem_public_key_len ||
        kem_public_key_len > sizeof(client_mlkem_public) ||
        kem_ciphertext_len > sizeof(server_mlkem_ciphertext))
    {
        fprintf(stderr, "CLIENT_HELLO length does not match its KEM profile.\n");
        goto cleanup;
    }

    memcpy(
        client_mlkem_public,
        client_hello + X25519_PUBLIC_KEY_SIZE + 1,
        kem_public_key_len
    );

    printf(
        "[+] Received Alice's X25519 public key\n"
    );

    printf(
        "[+] Received Alice's selected ML-KEM profile public key\n"
    );


    /* ========================================================
       Generate Bob's X25519 Key Pair
       ======================================================== */

    QueryPerformanceCounter(&stage_start);
    server_x25519_key =
        generate_x25519_keypair();
    QueryPerformanceCounter(&stage_finish);
    printf("[PHASE5_STAGE] X25519 key generation: %.3f ms\n",
           (double)(stage_finish.QuadPart - stage_start.QuadPart) *
               1000.0 / (double)timer_frequency.QuadPart);

    if (server_x25519_key == NULL)
    {
        goto cleanup;
    }

    size_t server_x25519_public_len =
        X25519_PUBLIC_KEY_SIZE;

    if (EVP_PKEY_get_raw_public_key(
            server_x25519_key,
            server_x25519_public,
            &server_x25519_public_len) <= 0)
    {
        print_openssl_error(
            "Failed to extract Bob's X25519 public key"
        );

        goto cleanup;
    }

    if (server_x25519_public_len !=
        X25519_PUBLIC_KEY_SIZE)
    {
        fprintf(
            stderr,
            "Unexpected X25519 public key size\n"
        );

        goto cleanup;
    }

    printf(
        "[+] Bob X25519 key pair generated\n"
    );


    /* ========================================================
       selected ML-KEM profile Encapsulation
       ======================================================== */

    QueryPerformanceCounter(&stage_start);
    oqs_status = OQS_KEM_encaps(
        kem,
        server_mlkem_ciphertext,
        mlkem_shared_secret,
        client_mlkem_public
    );
    QueryPerformanceCounter(&stage_finish);
    printf("[PHASE5_STAGE] selected ML-KEM profile encapsulation: %.3f ms\n",
           (double)(stage_finish.QuadPart - stage_start.QuadPart) *
               1000.0 / (double)timer_frequency.QuadPart);

    if (oqs_status != OQS_SUCCESS)
    {
        fprintf(
            stderr,
            "selected ML-KEM profile encapsulation failed\n"
        );

        goto cleanup;
    }

    printf(
        "[+] selected ML-KEM profile encapsulation successful\n"
    );


    /* ========================================================
       Build Authentication Transcript
       ======================================================== */

    if (build_auth_transcript(
            client_x25519_public,
            client_kem_profile_id,
            client_mlkem_public,
            kem_public_key_len,
            server_x25519_public,
            server_mlkem_ciphertext,
            kem_ciphertext_len,
            transcript,
            &transcript_len) != 0)
    {
        fprintf(
            stderr,
            "Failed to build authentication transcript\n"
        );

        goto cleanup;
    }

    if (transcript_len != AUTH_DOMAIN_SEPARATOR_SIZE + 3 +
            X25519_PUBLIC_KEY_SIZE + kem_public_key_len +
            X25519_PUBLIC_KEY_SIZE + kem_ciphertext_len)
    {
        fprintf(
            stderr,
            "Unexpected transcript size: %zu\n",
            transcript_len
        );

        goto cleanup;
    }

    printf(
        "[+] Authentication transcript created: %zu bytes\n",
        transcript_len
    );


    /* ========================================================
       ML-DSA-65 Signature
       ======================================================== */

    QueryPerformanceCounter(&stage_start);
    oqs_status = OQS_SIG_sign(
        sig,
        signature,
        &signature_len,
        transcript,
        transcript_len,
        mldsa_secret_key
    );
    QueryPerformanceCounter(&stage_finish);
    printf("[PHASE5_STAGE] ML-DSA-65 signing: %.3f ms\n",
           (double)(stage_finish.QuadPart - stage_start.QuadPart) *
               1000.0 / (double)timer_frequency.QuadPart);

    if (oqs_status != OQS_SUCCESS)
    {
        fprintf(
            stderr,
            "ML-DSA-65 signing failed\n"
        );

        goto cleanup;
    }

    if (signature_len != MLDSA65_SIGNATURE_SIZE)
    {
        fprintf(
            stderr,
            "Unexpected signature size: %zu\n",
            signature_len
        );

        goto cleanup;
    }

    printf(
        "[+] ML-DSA-65 handshake signature created\n"
    );


    /* ========================================================
       Build SERVER_HELLO
       ======================================================== */

    server_hello_offset = 0;

    /* Bob X25519 public key */

    memcpy(
        server_hello + server_hello_offset,
        server_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    server_hello_offset +=
        X25519_PUBLIC_KEY_SIZE;

    server_hello[server_hello_offset++] =
        client_kem_profile_id;


    /* ML-KEM ciphertext */

    memcpy(
        server_hello + server_hello_offset,
        server_mlkem_ciphertext,
        kem_ciphertext_len
    );

    server_hello_offset +=
        kem_ciphertext_len;


    /* Authentication algorithm */

    server_hello[server_hello_offset++] =
        AUTH_ALG_MLDSA65;


    /* Signature length */

    {
        uint16_t signature_length_network =
            htons((uint16_t)signature_len);

        memcpy(
            server_hello + server_hello_offset,
            &signature_length_network,
            sizeof(signature_length_network)
        );

        server_hello_offset +=
            sizeof(signature_length_network);
    }


    /* ML-DSA signature */

    memcpy(
        server_hello + server_hello_offset,
        signature,
        signature_len
    );

    server_hello_offset += signature_len;


    expected_server_hello_len = X25519_PUBLIC_KEY_SIZE + 1 +
        kem_ciphertext_len + 1 + AUTH_SIGNATURE_LENGTH_SIZE + signature_len;
    if (server_hello_offset != expected_server_hello_len ||
        server_hello_offset > sizeof(server_hello))
    {
        fprintf(
            stderr,
            "SERVER_HELLO size mismatch: %zu\n",
            server_hello_offset
        );

        goto cleanup;
    }


    /* ========================================================
       Send SERVER_HELLO
       ======================================================== */

    QueryPerformanceCounter(&stage_start);
    if (send_auth_packet(
            client_socket,
            PACKET_SERVER_HELLO,
            server_hello,
            (uint32_t)server_hello_offset) != 0)
    {
        fprintf(
            stderr,
            "Failed to send SERVER_HELLO\n"
        );

        goto cleanup;
    }
    QueryPerformanceCounter(&stage_finish);
    printf("[PHASE5_STAGE] Send SERVER_HELLO: %.3f ms\n",
           (double)(stage_finish.QuadPart - stage_start.QuadPart) *
               1000.0 / (double)timer_frequency.QuadPart);

    printf(
        "[+] Authenticated SERVER_HELLO sent\n"
    );


    /* ========================================================
       Derive X25519 Shared Secret
       ======================================================== */

    QueryPerformanceCounter(&stage_start);
    if (derive_x25519_shared_secret(
            server_x25519_key,
            client_x25519_public,
            x25519_shared_secret) != 0)
    {
        goto cleanup;
    }
    QueryPerformanceCounter(&stage_finish);
    printf("[PHASE5_STAGE] X25519 shared-secret derivation: %.3f ms\n",
           (double)(stage_finish.QuadPart - stage_start.QuadPart) *
               1000.0 / (double)timer_frequency.QuadPart);

    printf(
        "[+] X25519 shared secret derived\n"
    );


    /* ========================================================
       Derive Hybrid Session Key
       ======================================================== */

    QueryPerformanceCounter(&stage_start);
    if (derive_hybrid_session_key(
            x25519_shared_secret,
            mlkem_shared_secret,
            client_kem_profile_id,
#ifdef PHASE8_QKD_SIMULATOR
            transcript,
            transcript_len,
#endif
            hybrid_session_key) != 0)
    {
        goto cleanup;
    }
    QueryPerformanceCounter(&stage_finish);
    printf("[PHASE5_STAGE] HKDF-SHA-384: %.3f ms\n",
           (double)(stage_finish.QuadPart - stage_start.QuadPart) *
               1000.0 / (double)timer_frequency.QuadPart);

    if (!QueryThreadCycleTime(
            GetCurrentThread(),
            &cpu_cycles_key_ready))
    {
        fprintf(stderr, "Could not read server CPU cycle counter\n");
        goto cleanup;
    }

    printf(
        "[+] Hybrid session key derived\n"
    );
    printf("[PHASE5] Server main-thread cycles from accept through key ready: %llu\n",
           (unsigned long long)(cpu_cycles_key_ready - cpu_cycles_accept_start));


    /* ========================================================
       Phase 4.6 Fixed: Receive Two Packets
       ======================================================== */

    printf("\n");
    printf("===============================================\n");
    printf("       PHASE 4.6 FIXED REPLAY TEST\n");
#if defined(PHASE6_KEM_ADAPTIVE)
    printf("[PHASE6] Adaptive KEM support; minimum profile ID %u\n",
           minimum_profile_id);
#else
    printf("[PHASE6] Supported KEM profile: %s (ID %u)\n",
           PHASE6_KEM_ALGORITHM, PHASE6_KEM_PROFILE_ID);
#endif
    printf("===============================================\n");
    printf("[+] Replay protection enabled.\n");
    printf("[+] Expected sequence starts at 0.\n");

    for (;;)
    {
        unsigned char *current_payload = NULL;
        uint32_t current_payload_len = 0;
        unsigned char sequence_bytes[8];
        uint64_t received_sequence;

        if (recv_auth_packet(
                client_socket,
                &packet_type,
                &current_payload,
                &current_payload_len) != 0)
        {
            fprintf(
                stderr,
                "Failed to receive encrypted message\n"
            );

            if (current_payload != NULL)
            {
                free(current_payload);
            }

            goto cleanup;
        }

        if (packet_type != PACKET_ENCRYPTED_MESSAGE)
        {
            fprintf(
                stderr,
                "Expected ENCRYPTED_MESSAGE, received %u\n",
                packet_type
            );

            free(current_payload);
            goto cleanup;
        }

        if (current_payload_len <
            8 + GCM_NONCE_SIZE + GCM_TAG_SIZE + 1)
        {
            fprintf(
                stderr,
                "Protected encrypted payload is too small\n"
            );

            free(current_payload);
            goto cleanup;
        }

        memcpy(
            sequence_bytes,
            current_payload,
            sizeof(sequence_bytes)
        );

        received_sequence =
            decode_u64_be(sequence_bytes);

        printf("[+] Received packet with sequence %llu.\n",
               (unsigned long long)received_sequence);
        printf("[+] Expected sequence: %llu.\n",
               (unsigned long long)expected_sequence);

        /*
         * Freshness check happens before decryption. Once sequence 0
         * has been accepted, another packet carrying sequence 0 is
         * stale and is rejected as a replay.
         */
        if (received_sequence != expected_sequence)
        {
#ifdef PHASE8_QKD_SIMULATOR
            {
                static const unsigned char confirm_label[] =
                    "HybridPQC-Phase8-Replay-Rejected-v1";
                unsigned char confirm_payload[REPLAY_RESULT_PAYLOAD_SIZE];
                unsigned int confirm_mac_len = 0;

                confirm_payload[0] = 1;
                if (HMAC(EVP_sha384(), hybrid_session_key,
                         sizeof(hybrid_session_key), confirm_label,
                         sizeof(confirm_label) - 1, confirm_payload + 1,
                         &confirm_mac_len) == NULL || confirm_mac_len != 48 ||
                    send_auth_packet(client_socket, PACKET_REPLAY_RESULT,
                                     confirm_payload,
                                     sizeof(confirm_payload)) != 0) {
                    OPENSSL_cleanse(confirm_payload, sizeof(confirm_payload));
                    result = EXIT_FAILURE;
                    goto cleanup;
                }
                OPENSSL_cleanse(confirm_payload, sizeof(confirm_payload));
                printf("[PHASE8] Authenticated replay rejection result sent\n");
            }
#endif
            printf("\n");
            printf("===============================================\n");
            printf("       PHASE 4.6 SECURITY TEST: PASS\n");
            printf("===============================================\n");
            printf("[+] REPLAY DETECTED\n");
            printf("[+] Received sequence: %llu\n",
                   (unsigned long long)received_sequence);
            printf("[+] Expected sequence: %llu\n",
                   (unsigned long long)expected_sequence);
            printf("[+] Stale/out-of-order packet rejected before decryption.\n");
            printf("[+] Replay protection is active.\n");
            printf("RESULT: REPLAY PROTECTION VERIFIED\n");
            printf("===============================================\n");

            free(current_payload);
            current_payload = NULL;

            result = EXIT_SUCCESS;
            goto cleanup;
        }

        {
            const unsigned char *nonce =
                current_payload + 8;

            const unsigned char *ciphertext =
                current_payload + 8 + GCM_NONCE_SIZE;

            size_t ciphertext_len =
                current_payload_len -
                8 -
                GCM_NONCE_SIZE -
                GCM_TAG_SIZE;

            const unsigned char *tag =
                current_payload +
                8 +
                GCM_NONCE_SIZE +
                ciphertext_len;

            if (aes_gcm_decrypt(
                    hybrid_session_key,
                    sequence_bytes,
                    sizeof(sequence_bytes),
                    nonce,
                    ciphertext,
                    ciphertext_len,
                    tag,
                    plaintext,
                    &plaintext_len) != 0)
            {
                fprintf(
                    stderr,
                    "Message authentication failed\n"
                );

                free(current_payload);
                goto cleanup;
            }
        }

        printf("[+] Sequence %llu accepted and authenticated.\n",
               (unsigned long long)received_sequence);
        printf("[+] Message authentication succeeded.\n");
        printf("[+] Advancing expected sequence to %llu.\n",
               (unsigned long long)(expected_sequence + 1));

        expected_sequence++;

        free(current_payload);
        current_payload = NULL;

        /* Continue waiting for the deliberate replay packet. */
        printf("[TEST] Waiting for replayed packet...\n");
    }

    /* ========================================================
       Display Decrypted Message
       ======================================================== */

    printf("\n");
    printf("===============================================\n");
    printf("        AUTHENTICATED MESSAGE\n");
    printf("===============================================\n");

    printf(
        "Message: %.*s\n",
        (int)plaintext_len,
        plaintext
    );

    printf(
        "AES-256-GCM authentication: SUCCESS\n"
    );

    printf(
        "ML-DSA-65 authentication: SUCCESS\n"
    );

    printf(
        "Hybrid X25519 + selected ML-KEM profile: SUCCESS\n"
    );

    printf(
        "END-TO-END AUTHENTICATED HYBRID PQC VERIFIED\n"
    );

    printf(
        "===============================================\n"
    );

    result = EXIT_SUCCESS;


cleanup:

    {
        PROCESS_MEMORY_COUNTERS_EX memory_counters;
        memset(&memory_counters, 0, sizeof(memory_counters));
        memory_counters.cb = sizeof(memory_counters);
        if (GetProcessMemoryInfo(
                GetCurrentProcess(),
                (PROCESS_MEMORY_COUNTERS *)&memory_counters,
                sizeof(memory_counters)))
        {
            printf("[PHASE5] Server peak working set: %llu bytes\n",
                   (unsigned long long)memory_counters.PeakWorkingSetSize);
            printf("[PHASE5] Server private usage: %llu bytes\n",
                   (unsigned long long)memory_counters.PrivateUsage);
        }
    }

    if (encrypted_payload != NULL)
    {
        free(encrypted_payload);
        encrypted_payload = NULL;
    }

    if (client_socket != INVALID_SOCKET)
    {
        closesocket(client_socket);
    }

    if (server_socket != INVALID_SOCKET)
    {
        closesocket(server_socket);
    }

    if (server_x25519_key != NULL)
    {
        EVP_PKEY_free(server_x25519_key);
    }

    if (mldsa_secret_key != NULL)
    {
        OPENSSL_cleanse(
            mldsa_secret_key,
            MLDSA65_SECRET_KEY_SIZE
        );

        free(mldsa_secret_key);
    }

    OPENSSL_cleanse(
        mlkem_shared_secret,
        sizeof(mlkem_shared_secret)
    );

    OPENSSL_cleanse(
        x25519_shared_secret,
        sizeof(x25519_shared_secret)
    );

    OPENSSL_cleanse(
        hybrid_session_key,
        sizeof(hybrid_session_key)
    );

    OPENSSL_cleanse(
        transcript,
        sizeof(transcript)
    );

    OPENSSL_cleanse(
        signature,
        sizeof(signature)
    );

    OPENSSL_cleanse(
        plaintext,
        sizeof(plaintext)
    );

    if (kem != NULL)
    {
        OQS_KEM_free(kem);
    }

    if (sig != NULL)
    {
        OQS_SIG_free(sig);
    }

    WSACleanup();

    return result;
}
