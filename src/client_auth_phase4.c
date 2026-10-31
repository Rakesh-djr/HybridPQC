#define _CRT_SECURE_NO_WARNINGS

#include "protocol_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>


/* ============================================================
   Configuration
   ============================================================ */

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5555

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
    unsigned char *session_key)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;

    unsigned char combined_secret[64];

    const char *digest = "SHA384";

    const unsigned char info[] =
        "HybridPQC-X25519-MLKEM768-AES256GCM";

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
            (void *)info,
            sizeof(info) - 1
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
   Build Authentication Transcript
   ============================================================ */

static int build_auth_transcript(
    const unsigned char *client_x25519_public,
    const unsigned char *client_mlkem_public,
    const unsigned char *server_x25519_public,
    const unsigned char *server_mlkem_ciphertext,
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
        MLKEM768_PUBLIC_KEY_SIZE
    );

    offset += MLKEM768_PUBLIC_KEY_SIZE;

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
     * Bob ML-KEM ciphertext
     */

    memcpy(
        transcript + offset,
        server_mlkem_ciphertext,
        MLKEM768_CIPHERTEXT_SIZE
    );

    offset += MLKEM768_CIPHERTEXT_SIZE;

    *transcript_len = offset;

    return 0;
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

int main(void)
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
        MLKEM768_PUBLIC_KEY_SIZE
    ];

    unsigned char client_mlkem_secret_key[
        2400
    ];

    unsigned char server_x25519_public[
        X25519_PUBLIC_KEY_SIZE
    ];

    unsigned char server_mlkem_ciphertext[
        MLKEM768_CIPHERTEXT_SIZE
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

    uint8_t packet_type = 0;

    unsigned char client_hello[
        CLIENT_HELLO_SIZE
    ];

    unsigned char signature[
        MLDSA65_SIGNATURE_SIZE
    ];

    size_t signature_len = 0;

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

    const unsigned char plaintext[] =
        "Hello Bob! This message is protected by "
        "Authenticated Hybrid Post-Quantum Cryptography.";

    int result = EXIT_FAILURE;


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


    printf("\n");
    printf("===============================================\n");
    printf("   AUTHENTICATED HYBRID PQC CLIENT\n");
    printf("===============================================\n");
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
        OQS_KEM_alg_ml_kem_768
    );

    if (kem == NULL)
    {
        fprintf(
            stderr,
            "Failed to initialize ML-KEM-768\n"
        );

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
       Generate Alice ML-KEM-768 Key Pair
       ======================================================== */

    if (OQS_KEM_keypair(
            kem,
            client_mlkem_public,
            client_mlkem_secret_key) != OQS_SUCCESS)
    {
        fprintf(
            stderr,
            "ML-KEM-768 key generation failed\n"
        );

        goto cleanup;
    }

    printf(
        "[+] Alice ML-KEM-768 key pair generated\n"
    );


    /* ========================================================
       Build CLIENT_HELLO
       ======================================================== */

    memcpy(
        client_hello,
        client_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    memcpy(
        client_hello + X25519_PUBLIC_KEY_SIZE,
        client_mlkem_public,
        MLKEM768_PUBLIC_KEY_SIZE
    );


    /* ========================================================
       Connect to Bob
       ======================================================== */

    socket_fd =
        connect_to_server();

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

    if (send_auth_packet(
            socket_fd,
            PACKET_CLIENT_HELLO,
            client_hello,
            CLIENT_HELLO_SIZE) != 0)
    {
        fprintf(
            stderr,
            "Failed to send CLIENT_HELLO\n"
        );

        goto cleanup;
    }

    printf(
        "[+] CLIENT_HELLO sent\n"
    );


    /* ========================================================
       Receive SERVER_HELLO
       ======================================================== */

    if (recv_auth_packet(
            socket_fd,
            &packet_type,
            &server_hello,
            &server_hello_len) != 0)
    {
        fprintf(
            stderr,
            "Failed to receive SERVER_HELLO\n"
        );

        goto cleanup;
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

    if (server_hello_len !=
        SERVER_HELLO_AUTH_SIZE)
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


    /*
     * Bob X25519 public key
     */

    memcpy(
        server_x25519_public,
        server_hello + offset,
        X25519_PUBLIC_KEY_SIZE
    );

    offset += X25519_PUBLIC_KEY_SIZE;


    /*
     * ML-KEM ciphertext
     */

    memcpy(
        server_mlkem_ciphertext,
        server_hello + offset,
        MLKEM768_CIPHERTEXT_SIZE
    );

    offset += MLKEM768_CIPHERTEXT_SIZE;


    /*
     * Authentication algorithm
     */

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


    /*
     * Signature length
     */

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


    /*
     * Signature
     */

    memcpy(
        signature,
        server_hello + offset,
        signature_len
    );

    offset += signature_len;

    if (offset !=
        SERVER_HELLO_AUTH_SIZE)
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
            client_mlkem_public,
            server_x25519_public,
            server_mlkem_ciphertext,
            transcript,
            &transcript_len) != 0)
    {
        fprintf(
            stderr,
            "Failed to build authentication transcript\n"
        );

        goto cleanup;
    }

    if (transcript_len !=
        AUTH_TRANSCRIPT_SIZE)
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
       PHASE 4.1 SECURITY TEST
       Intentional Transcript Tampering
       ======================================================== */

    printf("\n");
    printf("===============================================\n");
    printf("       PHASE 4.1 SECURITY TEST\n");
    printf("===============================================\n");
    printf("[TEST] Tampering with authentication transcript...\n");

    /*
     * The transcript layout is:
     *
     * Domain Separator
     * Protocol Version
     * Authentication Algorithm
     * Alice X25519 Public Key
     * Alice ML-KEM Public Key
     * Bob X25519 Public Key
     * ML-KEM Ciphertext
     *
     * AUTH_DOMAIN_SEPARATOR_SIZE + 2 points to the
     * beginning of Alice's X25519 public key.
     *
     * +1 flips one byte inside Alice's X25519 public key.
     */

    transcript[
        AUTH_DOMAIN_SEPARATOR_SIZE + 2 + 1
    ] ^= 0x01;

    printf(
        "[TEST] One bit of Alice's X25519 public key "
        "was intentionally modified.\n"
    );

    printf(
        "[TEST] Verifying original ML-DSA signature "
        "against modified transcript...\n"
    );


    /* ========================================================
       Verify Bob's ML-DSA-65 Signature
       ======================================================== */

    OQS_STATUS verify_status;

    verify_status =
        OQS_SIG_verify(
            sig,
            transcript,
            transcript_len,
            signature,
            signature_len,
            server_mldsa_public_key
        );


    if (verify_status !=
        OQS_SUCCESS)
    {
        printf("\n");
        printf("===============================================\n");
        printf("       PHASE 4.1 SECURITY TEST: PASS\n");
        printf("===============================================\n");
        printf(
            "ML-DSA-65 verification: FAILED AS EXPECTED\n"
        );
        printf(
            "Modified authentication transcript was rejected.\n"
        );
        printf(
            "Connection will be terminated.\n"
        );
        printf("===============================================\n");
        printf(
            "RESULT: TRANSCRIPT TAMPERING DETECTED\n"
        );
        printf("===============================================\n\n");

        /*
         * This is an expected security failure.
         * Do not continue to key derivation or encryption.
         */

        result = EXIT_SUCCESS;

        goto cleanup;
    }


    /*
     * If verification succeeds after modifying the
     * signed transcript, the security test has failed.
     */

    printf("\n");
    printf("===============================================\n");
    printf("       PHASE 4.1 SECURITY TEST: FAIL\n");
    printf("===============================================\n");
    printf(
        "WARNING: Modified transcript was accepted!\n"
    );
    printf(
        "ML-DSA signature verification unexpectedly succeeded.\n"
    );
    printf("===============================================\n\n");

    goto cleanup;


cleanup:

    if (server_hello != NULL)
    {
        free(server_hello);
        server_hello = NULL;
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