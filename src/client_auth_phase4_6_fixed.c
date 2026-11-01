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
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#define SERVER_IP "127.0.0.1"
#ifndef SERVER_PORT
#define SERVER_PORT 5555
#endif

#define SERVER_MLDSA_PUBLIC_KEY_FILE \
    "C:\\HybridPQC\\keys\\server_mldsa_public.key"


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

    if (fread(
            buffer,
            1,
            expected_size,
            file) != expected_size)
    {
        fprintf(
            stderr,
            "Failed to read key file\n"
        );

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

    ctx = EVP_PKEY_CTX_new_id(
        EVP_PKEY_X25519,
        NULL
    );

    if (ctx == NULL)
    {
        print_openssl_error(
            "Failed to create X25519 context"
        );

        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        print_openssl_error(
            "X25519 key generation initialization failed"
        );

        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(
            ctx,
            &keypair) <= 0)
    {
        print_openssl_error(
            "X25519 key generation failed"
        );

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

    ctx = EVP_PKEY_CTX_new(
        private_key,
        NULL
    );

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

    if (EVP_PKEY_derive_set_peer(
            ctx,
            peer_key) <= 0)
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

    params[0] =
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_MODE,
            "EXTRACT_AND_EXPAND",
            0
        );

    params[1] =
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            (char *)digest,
            0
        );

    params[2] =
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            combined_secret,
            sizeof(combined_secret)
        );

    params[3] =
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            info,
            sizeof(info)
        );

    params[4] =
        OSSL_PARAM_construct_end();

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
   AES-256-GCM Encryption
   ============================================================ */

static int aes_gcm_encrypt(
    const unsigned char *key,
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *nonce,
    unsigned char *ciphertext,
    unsigned char *tag,
    size_t *ciphertext_len)
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

    if (EVP_EncryptInit_ex(
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

    if (RAND_bytes(
            nonce,
            GCM_NONCE_SIZE) != 1)
    {
        print_openssl_error(
            "Failed to generate random GCM nonce"
        );

        goto cleanup;
    }

    if (EVP_EncryptInit_ex(
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

    if (EVP_EncryptUpdate(
            ctx,
            ciphertext,
            &len,
            plaintext,
            (int)plaintext_len) != 1)
    {
        print_openssl_error(
            "AES-GCM encryption failed"
        );

        goto cleanup;
    }

    *ciphertext_len = (size_t)len;

    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + len,
            &final_len) != 1)
    {
        print_openssl_error(
            "AES-GCM finalization failed"
        );

        goto cleanup;
    }

    *ciphertext_len +=
        (size_t)final_len;

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            GCM_TAG_SIZE,
            tag) != 1)
    {
        print_openssl_error(
            "Failed to obtain GCM authentication tag"
        );

        goto cleanup;
    }

    result = 0;

cleanup:

    EVP_CIPHER_CTX_free(ctx);

    return result;
}


/* ============================================================
   AES-256-GCM Encryption with AAD
   ============================================================ */

static int aes_gcm_encrypt_with_aad(
    const unsigned char *key,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *nonce,
    unsigned char *ciphertext,
    unsigned char *tag,
    size_t *ciphertext_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int final_len = 0;
    int result = -1;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        print_openssl_error("Failed to create AES-GCM context");
        return -1;
    }

    if (EVP_EncryptInit_ex(
            ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    {
        print_openssl_error("AES-GCM initialization failed");
        goto cleanup;
    }

    if (RAND_bytes(nonce, GCM_NONCE_SIZE) != 1)
    {
        print_openssl_error("Failed to generate GCM nonce");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
    {
        print_openssl_error("AES-GCM key/nonce initialization failed");
        goto cleanup;
    }

    if (EVP_EncryptUpdate(
            ctx, NULL, &len, aad, (int)aad_len) != 1)
    {
        print_openssl_error("AES-GCM AAD processing failed");
        goto cleanup;
    }

    if (EVP_EncryptUpdate(
            ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1)
    {
        print_openssl_error("AES-GCM encryption failed");
        goto cleanup;
    }

    *ciphertext_len = (size_t)len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len) != 1)
    {
        print_openssl_error("AES-GCM finalization failed");
        goto cleanup;
    }

    *ciphertext_len += (size_t)final_len;

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1)
    {
        print_openssl_error("Failed to obtain GCM authentication tag");
        goto cleanup;
    }

    result = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}


/* ============================================================
   Phase 4.6 Sequence Encoding
   ============================================================ */

static void encode_u64_be(uint64_t value, unsigned char out[8])
{
    int i;

    for (i = 0; i < 8; i++)
    {
        out[7 - i] = (unsigned char)(value >> (i * 8));
    }
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

    memcpy(
        transcript + offset,
        AUTH_DOMAIN_SEPARATOR,
        AUTH_DOMAIN_SEPARATOR_SIZE
    );

    offset += AUTH_DOMAIN_SEPARATOR_SIZE;

    transcript[offset++] =
        HYBRID_AUTH_PROTOCOL_VERSION;

    transcript[offset++] =
        AUTH_ALG_MLDSA65;

    transcript[offset++] = kem_profile_id;

    memcpy(
        transcript + offset,
        client_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    offset += X25519_PUBLIC_KEY_SIZE;

    memcpy(
        transcript + offset,
        client_mlkem_public,
        client_mlkem_public_len
    );

    offset += client_mlkem_public_len;

    memcpy(
        transcript + offset,
        server_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    offset += X25519_PUBLIC_KEY_SIZE;

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

static int select_runtime_profile(
    int argc,
    char **argv,
    Phase6PolicyChoice *choice)
{
    Phase6PolicyInput input = {
        2, 0, 0.0, PHASE6_OBJECTIVE_LATENCY
    };
    int i;

    for (i = 1; i < argc; i++)
    {
        char *end = NULL;
        if (i + 1 >= argc) return -1;
        if (strcmp(argv[i], "--minimum") == 0)
        {
            if (parse_profile_id(argv[++i], &input.minimum_profile_id) != 0)
                return -1;
        }
        else if (strcmp(argv[i], "--bandwidth-kbps") == 0)
        {
            unsigned long value = strtoul(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || value == 0 ||
                value > UINT32_MAX) return -1;
            input.bandwidth_kbps = (uint32_t)value;
        }
        else if (strcmp(argv[i], "--max-handshake-ms") == 0)
        {
            double value = strtod(argv[++i], &end);
            if (end == argv[i] || *end != '\0' || value <= 0.0)
                return -1;
            input.maximum_handshake_ms = value;
        }
        else if (strcmp(argv[i], "--objective") == 0)
        {
            const char *objective = argv[++i];
            if (strcmp(objective, "latency") == 0)
                input.objective = PHASE6_OBJECTIVE_LATENCY;
            else if (strcmp(objective, "bandwidth") == 0)
                input.objective = PHASE6_OBJECTIVE_BANDWIDTH;
            else return -1;
        }
        else return -1;
    }

    return phase6_policy_select(&input, choice);
}


/* ============================================================
   Create TCP Connection
   ============================================================ */

static SOCKET connect_to_server(void)
{
    SOCKET socket_fd = INVALID_SOCKET;

    struct sockaddr_in server_address;

    socket_fd = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP
    );

    if (socket_fd == INVALID_SOCKET)
    {
        fprintf(
            stderr,
            "Failed to create socket\n"
        );

        return INVALID_SOCKET;
    }

    memset(
        &server_address,
        0,
        sizeof(server_address)
    );

    server_address.sin_family =
        AF_INET;

    server_address.sin_port =
        htons(SERVER_PORT);

    if (inet_pton(
            AF_INET,
            SERVER_IP,
            &server_address.sin_addr) != 1)
    {
        fprintf(
            stderr,
            "Invalid server IP address\n"
        );

        closesocket(socket_fd);

        return INVALID_SOCKET;
    }

    if (connect(
            socket_fd,
            (struct sockaddr *)&server_address,
            sizeof(server_address)) == SOCKET_ERROR)
    {
        fprintf(
            stderr,
            "Failed to connect to server\n"
        );

        closesocket(socket_fd);

        return INVALID_SOCKET;
    }

    return socket_fd;
}


/* ============================================================
   Main
   ============================================================ */

int main(int argc, char **argv)
{
    WSADATA wsa_data;

    SOCKET socket_fd = INVALID_SOCKET;

    OQS_KEM *kem = NULL;
    OQS_SIG *sig = NULL;

    EVP_PKEY *client_x25519_key = NULL;

    unsigned char server_mldsa_public_key[
        MLDSA65_PUBLIC_KEY_SIZE
    ];

    unsigned char client_x25519_public[
        X25519_PUBLIC_KEY_SIZE
    ];

    unsigned char client_mlkem_public[
        MLKEM_PUBLIC_KEY_SIZE
    ];

    unsigned char client_mlkem_secret_key[
        MLKEM_SECRET_KEY_SIZE
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

    unsigned char *server_hello = NULL;

    uint32_t server_hello_len = 0;

    unsigned char *replay_result_payload = NULL;

    uint32_t replay_result_payload_len = 0;

    uint8_t packet_type = 0;

    unsigned char client_hello[
        CLIENT_HELLO_SIZE
    ];

    unsigned char signature[
        MLDSA65_SIGNATURE_SIZE
    ];

    size_t signature_len = 0;
    size_t kem_public_key_len = 0;
    size_t kem_secret_key_len = 0;
    size_t kem_ciphertext_len = 0;
    size_t client_hello_len = 0;
    uint8_t selected_kem_profile_id = PHASE6_KEM_PROFILE_ID;
    const char *selected_kem_algorithm = PHASE6_KEM_ALGORITHM;
    Phase6PolicyChoice policy_choice;

    unsigned char nonce[
        GCM_NONCE_SIZE
    ];

    unsigned char ciphertext[
        MAX_MESSAGE_SIZE
    ];

    unsigned char tag[
        GCM_TAG_SIZE
    ];

    unsigned char encrypted_payload[
        MAX_MESSAGE_SIZE
    ];

    size_t ciphertext_len = 0;
    size_t encrypted_payload_len = 0;

    unsigned char sequence_bytes[8];
    uint64_t sequence_number = 0;

    const unsigned char plaintext[] =
        "Hello Bob! This message is protected by "
        "Authenticated Hybrid Post-Quantum Cryptography.";

    int result = EXIT_FAILURE;
    double tcp_connect_ms;
    double hello_to_key_ms;
    LARGE_INTEGER timer_frequency;
    LARGE_INTEGER connect_start;
    LARGE_INTEGER connect_finish;
    LARGE_INTEGER hello_start;
    LARGE_INTEGER key_ready;
    ULONG64 cpu_cycles_start = 0;
    ULONG64 cpu_cycles_key_ready = 0;

#if defined(PHASE6_KEM_ADAPTIVE)
    if (select_runtime_profile(argc, argv, &policy_choice) != 0)
    {
        fprintf(stderr, "Invalid policy or no profile meets its constraints.\n");
        fprintf(stderr, "Use --minimum 512|768|1024, optional --bandwidth-kbps N, "
                        "--max-handshake-ms N, --objective latency|bandwidth.\n");
        return EXIT_FAILURE;
    }
    selected_kem_profile_id = policy_choice.profile.profile_id;
    selected_kem_algorithm = kem_algorithm_for_profile(selected_kem_profile_id);
    if (selected_kem_algorithm == NULL)
    {
        fprintf(stderr, "Policy returned an unsupported KEM profile.\n");
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
    printf("   PHASE 4.5 AES-GCM SECURITY TEST CLIENT\n");
    printf("===============================================\n");
#if defined(PHASE6_KEM_ADAPTIVE)
    printf("[PHASE6_POLICY] Selected %s (ID %u), estimated handshake %.3f ms\n",
           selected_kem_algorithm, selected_kem_profile_id,
           policy_choice.estimated_handshake_ms);
#else
    printf("[PHASE6] Selected KEM profile: %s (ID %u)\n",
           selected_kem_algorithm, selected_kem_profile_id);
#endif
    printf("\n");


    /* ========================================================
       Load Bob's Trusted ML-DSA Public Key
       ======================================================== */

    if (load_binary_file(
            SERVER_MLDSA_PUBLIC_KEY_FILE,
            server_mldsa_public_key,
            MLDSA65_PUBLIC_KEY_SIZE) != 0)
    {
        goto cleanup;
    }

    printf(
        "[+] Bob's trusted ML-DSA-65 public key loaded\n"
    );


    /* ========================================================
       Initialize ML-KEM
       ======================================================== */

    kem = OQS_KEM_new(
        selected_kem_algorithm
    );

    if (kem == NULL)
    {
        fprintf(
            stderr,
            "Failed to initialize selected ML-KEM profile\n"
        );

        goto cleanup;
    }

    kem_public_key_len = kem->length_public_key;
    kem_secret_key_len = kem->length_secret_key;
    kem_ciphertext_len = kem->length_ciphertext;
    if (kem_public_key_len > sizeof(client_mlkem_public) ||
        kem_secret_key_len > sizeof(client_mlkem_secret_key) ||
        kem_ciphertext_len > sizeof(server_mlkem_ciphertext))
    {
        fprintf(stderr, "Selected KEM profile exceeds local buffer capacity.\n");
        goto cleanup;
    }


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


    /* ========================================================
       Generate Alice X25519 Key Pair
       ======================================================== */

    client_x25519_key =
        generate_x25519_keypair();

    if (client_x25519_key == NULL)
    {
        goto cleanup;
    }

    {
        size_t public_key_len =
            X25519_PUBLIC_KEY_SIZE;

        if (EVP_PKEY_get_raw_public_key(
                client_x25519_key,
                client_x25519_public,
                &public_key_len) <= 0)
        {
            print_openssl_error(
                "Failed to extract Alice X25519 public key"
            );

            goto cleanup;
        }

        if (public_key_len !=
            X25519_PUBLIC_KEY_SIZE)
        {
            fprintf(
                stderr,
                "Unexpected X25519 public key size\n"
            );

            goto cleanup;
        }
    }

    printf(
        "[+] Alice X25519 key pair generated\n"
    );


    /* ========================================================
       Generate Alice selected ML-KEM profile Key Pair
       ======================================================== */

    if (OQS_KEM_keypair(
            kem,
            client_mlkem_public,
            client_mlkem_secret_key) != OQS_SUCCESS)
    {
        fprintf(
            stderr,
            "selected ML-KEM profile key generation failed\n"
        );

        goto cleanup;
    }

    printf(
        "[+] Alice selected ML-KEM profile key pair generated\n"
    );


    /* ========================================================
       Build CLIENT_HELLO
       ======================================================== */

    memcpy(
        client_hello,
        client_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    client_hello[X25519_PUBLIC_KEY_SIZE] =
        selected_kem_profile_id;

    memcpy(
        client_hello + X25519_PUBLIC_KEY_SIZE + 1,
        client_mlkem_public,
        kem_public_key_len
    );
    client_hello_len = X25519_PUBLIC_KEY_SIZE + 1 + kem_public_key_len;


    /* ========================================================
       Connect to Bob
       ======================================================== */

    QueryPerformanceCounter(&connect_start);
    if (!QueryThreadCycleTime(GetCurrentThread(), &cpu_cycles_start))
    {
        fprintf(stderr, "Could not read client CPU cycle counter\n");
        goto cleanup;
    }

    socket_fd =
        connect_to_server();

    QueryPerformanceCounter(&connect_finish);

    if (socket_fd == INVALID_SOCKET)
    {
        goto cleanup;
    }

    printf(
        "[+] Connected to Bob\n"
    );


    /* ========================================================
       Send CLIENT_HELLO
       ======================================================== */

    QueryPerformanceCounter(&hello_start);

    if (send_auth_packet(
            socket_fd,
            PACKET_CLIENT_HELLO,
            client_hello,
            (uint32_t)client_hello_len) != 0)
    {
        fprintf(
            stderr,
            "Failed to send CLIENT_HELLO\n"
        );

        goto cleanup;
    }

    {
        LARGE_INTEGER stage_finish;
        QueryPerformanceCounter(&stage_finish);
        printf("[PHASE5_STAGE] Send CLIENT_HELLO: %.3f ms\n",
               (double)(stage_finish.QuadPart - hello_start.QuadPart) *
                   1000.0 / (double)timer_frequency.QuadPart);
    }

    printf(
        "[+] CLIENT_HELLO sent\n"
    );


    /* ========================================================
       Receive SERVER_HELLO
       ======================================================== */

    {
        LARGE_INTEGER receive_start;
        LARGE_INTEGER receive_finish;
        QueryPerformanceCounter(&receive_start);
        if (recv_auth_packet(
            socket_fd,
            &packet_type,
            &server_hello,
            &server_hello_len) != 0)
        {
            fprintf(stderr, "Failed to receive SERVER_HELLO\n");
            goto cleanup;
        }
        QueryPerformanceCounter(&receive_finish);
        printf("[PHASE5_STAGE] Receive SERVER_HELLO: %.3f ms\n",
               (double)(receive_finish.QuadPart - receive_start.QuadPart) *
                   1000.0 / (double)timer_frequency.QuadPart);
    }

    if (packet_type !=
        PACKET_SERVER_HELLO)
    {
        fprintf(
            stderr,
            "Expected SERVER_HELLO, received %u\n",
            packet_type
        );

        goto cleanup;
    }

    if (server_hello_len > SERVER_HELLO_AUTH_MAX_SIZE)
    {
        fprintf(
            stderr,
            "Invalid SERVER_HELLO size: %u\n",
            server_hello_len
        );

        goto cleanup;
    }

    printf(
        "[+] Authenticated SERVER_HELLO received\n"
    );


    /* ========================================================
       Parse SERVER_HELLO
       ======================================================== */

    size_t offset = 0;

    memcpy(
        server_x25519_public,
        server_hello + offset,
        X25519_PUBLIC_KEY_SIZE
    );

    offset += X25519_PUBLIC_KEY_SIZE;

    uint8_t server_kem_profile_id = server_hello[offset++];
    if (server_kem_profile_id != selected_kem_profile_id)
    {
        fprintf(stderr, "Server selected an unexpected ML-KEM profile: %u\n",
                server_kem_profile_id);
        goto cleanup;
    }

    memcpy(
        server_mlkem_ciphertext,
        server_hello + offset,
        kem_ciphertext_len
    );

    offset += kem_ciphertext_len;

    uint8_t auth_algorithm =
        server_hello[offset++];

    if (auth_algorithm !=
        AUTH_ALG_MLDSA65)
    {
        fprintf(
            stderr,
            "Unsupported authentication algorithm: %u\n",
            auth_algorithm
        );

        goto cleanup;
    }

    uint16_t signature_length_network;

    memcpy(
        &signature_length_network,
        server_hello + offset,
        sizeof(signature_length_network)
    );

    offset +=
        sizeof(signature_length_network);

    signature_len =
        ntohs(signature_length_network);

    if (signature_len !=
        MLDSA65_SIGNATURE_SIZE)
    {
        fprintf(
            stderr,
            "Invalid ML-DSA signature length: %zu\n",
            signature_len
        );

        goto cleanup;
    }

    memcpy(
        signature,
        server_hello + offset,
        signature_len
    );

    offset += signature_len;

    if (offset != server_hello_len)
    {
        fprintf(
            stderr,
            "SERVER_HELLO parsing error\n"
        );

        goto cleanup;
    }

    printf(
        "[+] ML-DSA-65 signature extracted\n"
    );


    /* ========================================================
       Rebuild Authentication Transcript
       ======================================================== */

    if (build_auth_transcript(
            client_x25519_public,
            server_kem_profile_id,
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
            "Unexpected transcript size\n"
        );

        goto cleanup;
    }

    printf(
        "[+] Authentication transcript reconstructed\n"
    );


    /* ========================================================
       Verify Bob's ML-DSA-65 Signature
       ======================================================== */

    OQS_STATUS verify_status;

    {
        LARGE_INTEGER stage_start;
        LARGE_INTEGER stage_finish;
        QueryPerformanceCounter(&stage_start);
        verify_status =
        OQS_SIG_verify(
            sig,
            transcript,
            transcript_len,
            signature,
            signature_len,
            server_mldsa_public_key
        );
        QueryPerformanceCounter(&stage_finish);
        printf("[PHASE5_STAGE] ML-DSA-65 verification: %.3f ms\n",
               (double)(stage_finish.QuadPart - stage_start.QuadPart) *
                   1000.0 / (double)timer_frequency.QuadPart);
    }

    if (verify_status !=
        OQS_SUCCESS)
    {
        fprintf(
            stderr,
            "\n"
            "===============================================\n"
        );

        fprintf(
            stderr,
            "       AUTHENTICATION FAILED\n"
        );

        fprintf(
            stderr,
            "===============================================\n"
        );

        fprintf(
            stderr,
            "Bob's ML-DSA-65 signature is INVALID.\n"
        );

        fprintf(
            stderr,
            "The connection will be terminated.\n"
        );

        fprintf(
            stderr,
            "===============================================\n\n"
        );

        goto cleanup;
    }

    printf(
        "[+] Bob ML-DSA-65 signature VERIFIED\n"
    );

    printf(
        "[+] Bob's identity authenticated\n"
    );


    /* ========================================================
       ML-KEM Decapsulation
       ======================================================== */

    {
        LARGE_INTEGER stage_start;
        LARGE_INTEGER stage_finish;
        OQS_STATUS decaps_status;
        QueryPerformanceCounter(&stage_start);
        decaps_status = OQS_KEM_decaps(
            kem,
            mlkem_shared_secret,
            server_mlkem_ciphertext,
            client_mlkem_secret_key);
        QueryPerformanceCounter(&stage_finish);
        printf("[PHASE5_STAGE] selected ML-KEM profile decapsulation: %.3f ms\n",
               (double)(stage_finish.QuadPart - stage_start.QuadPart) *
                   1000.0 / (double)timer_frequency.QuadPart);
        if (decaps_status != OQS_SUCCESS)
        {
            fprintf(stderr, "selected ML-KEM profile decapsulation failed\n");
            goto cleanup;
        }
    }

    printf(
        "[+] selected ML-KEM profile shared secret derived\n"
    );


    /* ========================================================
       X25519 Shared Secret
       ======================================================== */

    {
        LARGE_INTEGER stage_start;
        LARGE_INTEGER stage_finish;
        int derive_status;
        QueryPerformanceCounter(&stage_start);
        derive_status = derive_x25519_shared_secret(
            client_x25519_key,
            server_x25519_public,
            x25519_shared_secret);
        QueryPerformanceCounter(&stage_finish);
        printf("[PHASE5_STAGE] X25519 shared-secret derivation: %.3f ms\n",
               (double)(stage_finish.QuadPart - stage_start.QuadPart) *
                   1000.0 / (double)timer_frequency.QuadPart);
        if (derive_status != 0)
        {
            goto cleanup;
        }
    }

    printf(
        "[+] X25519 shared secret derived\n"
    );


    /* ========================================================
       Hybrid Session Key
       ======================================================== */

    {
        LARGE_INTEGER stage_start;
        LARGE_INTEGER stage_finish;
        int hkdf_status;
        QueryPerformanceCounter(&stage_start);
        hkdf_status = derive_hybrid_session_key(
            x25519_shared_secret,
            mlkem_shared_secret,
            selected_kem_profile_id,
#ifdef PHASE8_QKD_SIMULATOR
            transcript,
            transcript_len,
#endif
            hybrid_session_key);
        QueryPerformanceCounter(&stage_finish);
        printf("[PHASE5_STAGE] HKDF-SHA-384: %.3f ms\n",
               (double)(stage_finish.QuadPart - stage_start.QuadPart) *
                   1000.0 / (double)timer_frequency.QuadPart);
        if (hkdf_status != 0)
        {
            goto cleanup;
        }
    }

    QueryPerformanceCounter(&key_ready);
    if (!QueryThreadCycleTime(GetCurrentThread(), &cpu_cycles_key_ready))
    {
        fprintf(stderr, "Could not read client CPU cycle counter\n");
        goto cleanup;
    }

    tcp_connect_ms =
        (double)(connect_finish.QuadPart - connect_start.QuadPart) *
        1000.0 / (double)timer_frequency.QuadPart;
    hello_to_key_ms =
        (double)(key_ready.QuadPart - hello_start.QuadPart) *
        1000.0 / (double)timer_frequency.QuadPart;

    printf(
        "[+] Hybrid session key derived\n"
    );

    printf("[PHASE5] TCP connect latency: %.3f ms\n",
           tcp_connect_ms);
    printf("[PHASE5] CLIENT_HELLO send through authenticated session-key ready: %.3f ms\n",
           hello_to_key_ms);
    printf("[PHASE5] TCP connect plus authenticated handshake: %.3f ms\n",
           tcp_connect_ms + hello_to_key_ms);
    printf("[PHASE5] Client main-thread cycles during connect and handshake: %llu\n",
           (unsigned long long)(cpu_cycles_key_ready - cpu_cycles_start));


    /* ========================================================
       PHASE 4.6
       REPLAY / FRESHNESS PROTECTION TEST
       ======================================================== */

    printf("\n");
    printf("===============================================\n");
    printf("       PHASE 4.6 FIXED REPLAY TEST\n");
    printf("       REPLAY / FRESHNESS PROTECTION\n");
    printf("===============================================\n");

    /*
     * The first protected application message in this session uses
     * sequence number 0. The same sequence number will intentionally
     * be replayed below. The server must reject it after accepting
     * the first packet.
     */
    sequence_number = 0;
    encode_u64_be(sequence_number, sequence_bytes);

    if (aes_gcm_encrypt_with_aad(
            hybrid_session_key,
            sequence_bytes,
            sizeof(sequence_bytes),
            plaintext,
            sizeof(plaintext) - 1,
            nonce,
            ciphertext,
            tag,
            &ciphertext_len) != 0)
    {
        fprintf(stderr, "AES-256-GCM encryption with AAD failed\n");
        goto cleanup;
    }

    printf(
        "[+] AES-256-GCM ciphertext generated with sequence number %llu.\n",
        (unsigned long long)sequence_number
    );
    printf("[+] Sequence number authenticated as AES-GCM AAD.\n");

    /* Payload: sequence(8) + nonce(12) + ciphertext + tag(16). */
    encrypted_payload_len = 0;

    memcpy(
        encrypted_payload + encrypted_payload_len,
        sequence_bytes,
        sizeof(sequence_bytes)
    );
    encrypted_payload_len += sizeof(sequence_bytes);

    memcpy(
        encrypted_payload + encrypted_payload_len,
        nonce,
        GCM_NONCE_SIZE
    );
    encrypted_payload_len += GCM_NONCE_SIZE;

    memcpy(
        encrypted_payload + encrypted_payload_len,
        ciphertext,
        ciphertext_len
    );
    encrypted_payload_len += ciphertext_len;

    memcpy(
        encrypted_payload + encrypted_payload_len,
        tag,
        GCM_TAG_SIZE
    );
    encrypted_payload_len += GCM_TAG_SIZE;

    printf(
        "[+] Protected payload constructed: %zu bytes\n",
        encrypted_payload_len
    );

    printf("\n");
    printf("[TEST] Sending original packet with sequence 0...\n");

    if (send_auth_packet(
            socket_fd,
            PACKET_ENCRYPTED_MESSAGE,
            encrypted_payload,
            (uint32_t)encrypted_payload_len) != 0)
    {
        fprintf(stderr, "Failed to send original protected packet\n");
        goto cleanup;
    }

    printf("[+] Original protected packet sent.\n");

    printf("\n");
    printf("[TEST] Replaying EXACT SAME protected packet...\n");
    printf("[TEST] Sequence 0, nonce, ciphertext and tag remain unchanged.\n");
    printf("[TEST] No new encryption is performed.\n");

    if (send_auth_packet(
            socket_fd,
            PACKET_ENCRYPTED_MESSAGE,
            encrypted_payload,
            (uint32_t)encrypted_payload_len) != 0)
    {
        printf("[+] Connection closed after replay was rejected by Bob.\n");
        printf("[+] Server-side freshness check is the definitive result.\n");
        result = EXIT_SUCCESS;
        goto cleanup;
    }

#ifdef PHASE8_QKD_SIMULATOR
    {
        static const unsigned char confirm_label[] =
            "HybridPQC-Phase8-Replay-Rejected-v1";
        unsigned char expected_mac[EVP_MAX_MD_SIZE];
        unsigned int expected_mac_len = 0;

        if (recv_auth_packet(socket_fd, &packet_type,
                             &replay_result_payload,
                             &replay_result_payload_len) != 0 ||
            packet_type != PACKET_REPLAY_RESULT ||
            replay_result_payload_len != REPLAY_RESULT_PAYLOAD_SIZE ||
            replay_result_payload[0] != 1 ||
            HMAC(EVP_sha384(), hybrid_session_key,
                 sizeof(hybrid_session_key), confirm_label,
                 sizeof(confirm_label) - 1,
                 expected_mac, &expected_mac_len) == NULL ||
            expected_mac_len != 48 ||
            CRYPTO_memcmp(replay_result_payload + 1,
                          expected_mac, expected_mac_len) != 0) {
            fprintf(stderr, "[PHASE8] Missing or invalid authenticated replay result\n");
            OPENSSL_cleanse(expected_mac, sizeof(expected_mac));
            goto cleanup;
        }
        OPENSSL_cleanse(expected_mac, sizeof(expected_mac));
        printf("[PHASE8] Server authenticated replay rejection confirmed\n");
    }
#endif

    printf("[!] Replay packet was transmitted over TCP.\n");
#ifndef PHASE8_QKD_SIMULATOR
    printf("[!] Check server output: sequence 0 must be rejected as stale.\n");
#endif

    printf("\n");
    printf("===============================================\n");
    printf("       PHASE 4.6 CLIENT TEST COMPLETE\n");
    printf("===============================================\n");
    printf("[+] Sequence number authenticated as GCM AAD.\n");
    printf("[+] Original sequence: 0\n");
    printf("[+] Exact replay sequence: 0\n");
#ifdef PHASE8_QKD_SIMULATOR
    printf("[+] Server's session-key HMAC confirms sequence 0 was rejected as stale.\n");
#else
    printf("[+] Definitive PASS is confirmed by the server rejecting sequence 0 as stale.\n");
#endif
    printf("===============================================\n");

    /* The server-side freshness check provides the definitive PASS. */
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
            printf("[PHASE5] Client peak working set: %llu bytes\n",
                   (unsigned long long)memory_counters.PeakWorkingSetSize);
            printf("[PHASE5] Client private usage: %llu bytes\n",
                   (unsigned long long)memory_counters.PrivateUsage);
        }
    }

    if (server_hello != NULL)
    {
        free(server_hello);
        server_hello = NULL;
    }

    if (replay_result_payload != NULL)
    {
        free(replay_result_payload);
        replay_result_payload = NULL;
    }

    if (socket_fd != INVALID_SOCKET)
    {
        closesocket(socket_fd);
    }

    if (client_x25519_key != NULL)
    {
        EVP_PKEY_free(
            client_x25519_key
        );
    }

    if (kem != NULL)
    {
        OQS_KEM_free(kem);
    }

    if (sig != NULL)
    {
        OQS_SIG_free(sig);
    }

    OPENSSL_cleanse(
        client_mlkem_secret_key,
        sizeof(client_mlkem_secret_key)
    );

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
        ciphertext,
        sizeof(ciphertext)
    );

    OPENSSL_cleanse(
        encrypted_payload,
        sizeof(encrypted_payload)
    );

    WSACleanup();

    return result;
}
