#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <oqs/oqs.h>

#include "protocol.h"

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5555

#define HYBRID_KEY_SIZE 32
#define X25519_SHARED_SECRET_SIZE 32
#define MLKEM_SHARED_SECRET_SIZE 32

#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16

#define PLAINTEXT "Hello Bob! This message is protected by Hybrid Post-Quantum Cryptography."

static void print_openssl_error(const char *message)
{
    fprintf(stderr, "[CLIENT] %s\n", message);
    ERR_print_errors_fp(stderr);
}

/* ---------------------------------------------------------
   X25519 KEY GENERATION
   --------------------------------------------------------- */

static int generate_x25519_keypair(
    EVP_PKEY **private_key,
    unsigned char public_key[X25519_PUBLIC_KEY_SIZE])
{
    EVP_PKEY_CTX *ctx = NULL;
    size_t public_key_length = X25519_PUBLIC_KEY_SIZE;

    *private_key = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (ctx == NULL)
    {
        print_openssl_error("Failed to create X25519 context");
        return 0;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        print_openssl_error("X25519 keygen initialization failed");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_keygen(ctx, private_key) <= 0)
    {
        print_openssl_error("X25519 key generation failed");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_get_raw_public_key(
            *private_key,
            public_key,
            &public_key_length) <= 0)
    {
        print_openssl_error("Failed to extract X25519 public key");
        EVP_PKEY_free(*private_key);
        *private_key = NULL;
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);

    if (public_key_length != X25519_PUBLIC_KEY_SIZE)
    {
        fprintf(stderr,
                "[CLIENT] Invalid X25519 public key size\n");

        EVP_PKEY_free(*private_key);
        *private_key = NULL;

        return 0;
    }

    return 1;
}

/* ---------------------------------------------------------
   X25519 SHARED SECRET
   --------------------------------------------------------- */

static int derive_x25519_shared_secret(
    EVP_PKEY *private_key,
    const unsigned char peer_public_key[X25519_PUBLIC_KEY_SIZE],
    unsigned char shared_secret[X25519_SHARED_SECRET_SIZE])
{
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    size_t shared_secret_length =
        X25519_SHARED_SECRET_SIZE;

    peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        NULL,
        peer_public_key,
        X25519_PUBLIC_KEY_SIZE);

    if (peer_key == NULL)
    {
        print_openssl_error(
            "Failed to create peer X25519 key");

        return 0;
    }

    ctx = EVP_PKEY_CTX_new(private_key, NULL);

    if (ctx == NULL)
    {
        print_openssl_error(
            "Failed to create X25519 derive context");

        EVP_PKEY_free(peer_key);

        return 0;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        print_openssl_error(
            "X25519 derive initialization failed");

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);

        return 0;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
    {
        print_openssl_error(
            "EVP_PKEY_derive_set_peer failed");

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);

        return 0;
    }

    if (EVP_PKEY_derive(
            ctx,
            shared_secret,
            &shared_secret_length) <= 0)
    {
        print_openssl_error(
            "X25519 shared secret derivation failed");

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);

        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);

    if (shared_secret_length !=
        X25519_SHARED_SECRET_SIZE)
    {
        fprintf(stderr,
                "[CLIENT] Invalid X25519 shared secret size\n");

        return 0;
    }

    return 1;
}

/* ---------------------------------------------------------
   HKDF-SHA-384
   --------------------------------------------------------- */

static int derive_hybrid_key(
    const unsigned char x25519_secret[X25519_SHARED_SECRET_SIZE],
    const unsigned char mlkem_secret[MLKEM_SHARED_SECRET_SIZE],
    unsigned char hybrid_key[HYBRID_KEY_SIZE])
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;

    unsigned char combined_secret[
        X25519_SHARED_SECRET_SIZE +
        MLKEM_SHARED_SECRET_SIZE];

    const char *digest = "SHA384";

    const unsigned char info[] =
        "HybridPQC-X25519-MLKEM768-AES256GCM";

    memcpy(
        combined_secret,
        x25519_secret,
        X25519_SHARED_SECRET_SIZE);

    memcpy(
        combined_secret +
        X25519_SHARED_SECRET_SIZE,
        mlkem_secret,
        MLKEM_SHARED_SECRET_SIZE);

    kdf = EVP_KDF_fetch(
        NULL,
        "HKDF",
        NULL);

    if (kdf == NULL)
    {
        print_openssl_error(
            "Failed to fetch HKDF");

        return 0;
    }

    kdf_ctx = EVP_KDF_CTX_new(kdf);

    if (kdf_ctx == NULL)
    {
        print_openssl_error(
            "Failed to create HKDF context");

        EVP_KDF_free(kdf);

        return 0;
    }

    OSSL_PARAM params[] = {

        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_MODE,
            "EXTRACT_AND_EXPAND",
            0),

        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            (char *)digest,
            0),

        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            combined_secret,
            sizeof(combined_secret)),

        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            (void *)info,
            sizeof(info) - 1),

        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(
            kdf_ctx,
            hybrid_key,
            HYBRID_KEY_SIZE,
            params) <= 0)
    {
        print_openssl_error(
            "HKDF-SHA-384 derivation failed");

        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);

        return 0;
    }

    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);

    return 1;
}

/* ---------------------------------------------------------
   AES-256-GCM ENCRYPTION
   --------------------------------------------------------- */

static int aes_gcm_encrypt(
    const unsigned char *plaintext,
    int plaintext_length,
    const unsigned char key[HYBRID_KEY_SIZE],
    unsigned char nonce[GCM_NONCE_SIZE],
    unsigned char *ciphertext,
    unsigned char tag[GCM_TAG_SIZE])
{
    EVP_CIPHER_CTX *ctx = NULL;

    int len = 0;
    int ciphertext_length = 0;

    if (RAND_bytes(
            nonce,
            GCM_NONCE_SIZE) != 1)
    {
        print_openssl_error(
            "Failed to generate GCM nonce");

        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
    {
        print_openssl_error(
            "Failed to create AES-GCM context");

        return 0;
    }

    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) <= 0)
    {
        print_openssl_error(
            "AES-GCM initialization failed");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }

    if (EVP_EncryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce) <= 0)
    {
        print_openssl_error(
            "AES-GCM key/nonce initialization failed");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }

    if (EVP_EncryptUpdate(
            ctx,
            ciphertext,
            &len,
            plaintext,
            plaintext_length) <= 0)
    {
        print_openssl_error(
            "AES-GCM encryption failed");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }

    ciphertext_length = len;

    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + ciphertext_length,
            &len) <= 0)
    {
        print_openssl_error(
            "AES-GCM finalization failed");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }

    ciphertext_length += len;

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            GCM_TAG_SIZE,
            tag) <= 0)
    {
        print_openssl_error(
            "Failed to obtain GCM authentication tag");

        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_length;
}

/* ---------------------------------------------------------
   MAIN
   --------------------------------------------------------- */

int main(void)
{
    WSADATA wsa_data;

    SOCKET socket_fd = INVALID_SOCKET;

    struct sockaddr_in server_address;

    EVP_PKEY *x25519_private_key = NULL;

    OQS_KEM *kem = NULL;

    unsigned char x25519_public_key[
        X25519_PUBLIC_KEY_SIZE];

    unsigned char server_x25519_public_key[
        X25519_PUBLIC_KEY_SIZE];

    unsigned char mlkem_public_key[
        MLKEM768_PUBLIC_KEY_SIZE];

    unsigned char mlkem_secret_key[
        2400];

    unsigned char server_mlkem_ciphertext[
        MLKEM768_CIPHERTEXT_SIZE];

    unsigned char x25519_shared_secret[
        X25519_SHARED_SECRET_SIZE];

    unsigned char mlkem_shared_secret[
        MLKEM_SHARED_SECRET_SIZE];

    unsigned char hybrid_key[
        HYBRID_KEY_SIZE];

    unsigned char nonce[
        GCM_NONCE_SIZE];

    unsigned char ciphertext[
        MAX_MESSAGE_SIZE];

    unsigned char tag[
        GCM_TAG_SIZE];

    unsigned char client_hello[
        X25519_PUBLIC_KEY_SIZE +
        MLKEM768_PUBLIC_KEY_SIZE];

    unsigned char *server_hello = NULL;

    uint8_t packet_type = 0;

    uint32_t packet_length = 0;

    int ciphertext_length = 0;

    int result = EXIT_FAILURE;

    memset(
        x25519_public_key,
        0,
        sizeof(x25519_public_key));

    memset(
        server_x25519_public_key,
        0,
        sizeof(server_x25519_public_key));

    memset(
        mlkem_public_key,
        0,
        sizeof(mlkem_public_key));

    memset(
        mlkem_secret_key,
        0,
        sizeof(mlkem_secret_key));

    memset(
        server_mlkem_ciphertext,
        0,
        sizeof(server_mlkem_ciphertext));

    memset(
        x25519_shared_secret,
        0,
        sizeof(x25519_shared_secret));

    memset(
        mlkem_shared_secret,
        0,
        sizeof(mlkem_shared_secret));

    memset(
        hybrid_key,
        0,
        sizeof(hybrid_key));

    memset(
        nonce,
        0,
        sizeof(nonce));

    memset(
        ciphertext,
        0,
        sizeof(ciphertext));

    memset(
        tag,
        0,
        sizeof(tag));

    printf("\n");
    printf("========================================\n");
    printf(" Hybrid PQC Secure Client\n");
    printf(" X25519 + ML-KEM-768 + AES-256-GCM\n");
    printf("========================================\n\n");

    /* -----------------------------------------------------
       WINSOCK INITIALIZATION
       ----------------------------------------------------- */

    if (WSAStartup(
            MAKEWORD(2, 2),
            &wsa_data) != 0)
    {
        fprintf(
            stderr,
            "[CLIENT] WSAStartup failed\n");

        goto cleanup;
    }

    printf(
        "[CLIENT] Winsock initialized\n");

    /* -----------------------------------------------------
       CREATE SOCKET
       ----------------------------------------------------- */

    socket_fd = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP);

    if (socket_fd == INVALID_SOCKET)
    {
        fprintf(
            stderr,
            "[CLIENT] Socket creation failed\n");

        goto cleanup;
    }

    /* -----------------------------------------------------
       SERVER ADDRESS
       ----------------------------------------------------- */

    memset(
        &server_address,
        0,
        sizeof(server_address));

    server_address.sin_family = AF_INET;

    server_address.sin_port =
        htons(SERVER_PORT);

    if (InetPtonA(
            AF_INET,
            SERVER_IP,
            &server_address.sin_addr) != 1)
    {
        fprintf(
            stderr,
            "[CLIENT] Invalid server IP\n");

        goto cleanup;
    }

    /* -----------------------------------------------------
       CONNECT
       ----------------------------------------------------- */

    printf(
        "[CLIENT] Connecting to %s:%d...\n",
        SERVER_IP,
        SERVER_PORT);

    if (connect(
            socket_fd,
            (struct sockaddr *)&server_address,
            sizeof(server_address)) == SOCKET_ERROR)
    {
        fprintf(
            stderr,
            "[CLIENT] Connection failed. "
            "Is server.exe running?\n");

        goto cleanup;
    }

    printf(
        "[CLIENT] Connected to server\n\n");

    /* -----------------------------------------------------
       X25519 KEYPAIR
       ----------------------------------------------------- */

    printf(
        "[CLIENT] Generating X25519 keypair...\n");

    if (!generate_x25519_keypair(
            &x25519_private_key,
            x25519_public_key))
    {
        goto cleanup;
    }

    printf(
        "[CLIENT] X25519 keypair generated\n");

    /* -----------------------------------------------------
       ML-KEM-768 KEYPAIR
       ----------------------------------------------------- */

    printf(
        "[CLIENT] Generating ML-KEM-768 keypair...\n");

    kem = OQS_KEM_new(
        OQS_KEM_alg_ml_kem_768);

    if (kem == NULL)
    {
        fprintf(
            stderr,
            "[CLIENT] Failed to create ML-KEM-768\n");

        goto cleanup;
    }

    if (kem->length_public_key !=
        MLKEM768_PUBLIC_KEY_SIZE)
    {
        fprintf(
            stderr,
            "[CLIENT] Unexpected ML-KEM public key size\n");

        goto cleanup;
    }

    if (kem->length_ciphertext !=
        MLKEM768_CIPHERTEXT_SIZE)
    {
        fprintf(
            stderr,
            "[CLIENT] Unexpected ML-KEM ciphertext size\n");

        goto cleanup;
    }

    if (OQS_KEM_keypair(
            kem,
            mlkem_public_key,
            mlkem_secret_key) != OQS_SUCCESS)
    {
        fprintf(
            stderr,
            "[CLIENT] ML-KEM-768 key generation failed\n");

        goto cleanup;
    }

    printf(
        "[CLIENT] ML-KEM-768 keypair generated\n");

    /* -----------------------------------------------------
       BUILD CLIENT HELLO
       ----------------------------------------------------- */

    memcpy(
        client_hello,
        x25519_public_key,
        X25519_PUBLIC_KEY_SIZE);

    memcpy(
        client_hello +
        X25519_PUBLIC_KEY_SIZE,
        mlkem_public_key,
        MLKEM768_PUBLIC_KEY_SIZE);

    printf(
        "[CLIENT] Sending CLIENT_HELLO...\n");

    if (!send_packet(
            socket_fd,
            PACKET_CLIENT_HELLO,
            client_hello,
            sizeof(client_hello)))
    {
        fprintf(
            stderr,
            "[CLIENT] Failed to send CLIENT_HELLO\n");

        goto cleanup;
    }

    printf(
        "[CLIENT] CLIENT_HELLO sent\n");

    /* -----------------------------------------------------
       RECEIVE SERVER HELLO
       ----------------------------------------------------- */

    printf(
        "[CLIENT] Waiting for SERVER_HELLO...\n");

    if (!recv_packet(
            socket_fd,
            &packet_type,
            &server_hello,
            &packet_length))
    {
        fprintf(
            stderr,
            "[CLIENT] Failed to receive SERVER_HELLO\n");

        goto cleanup;
    }

    if (packet_type != PACKET_SERVER_HELLO)
    {
        fprintf(
            stderr,
            "[CLIENT] Unexpected packet type: %u\n",
            packet_type);

        goto cleanup;
    }

    if (packet_length !=
        X25519_PUBLIC_KEY_SIZE +
        MLKEM768_CIPHERTEXT_SIZE)
    {
        fprintf(
            stderr,
            "[CLIENT] Invalid SERVER_HELLO length: %u\n",
            packet_length);

        goto cleanup;
    }

    memcpy(
        server_x25519_public_key,
        server_hello,
        X25519_PUBLIC_KEY_SIZE);

    memcpy(
        server_mlkem_ciphertext,
        server_hello +
        X25519_PUBLIC_KEY_SIZE,
        MLKEM768_CIPHERTEXT_SIZE);

    printf(
        "[CLIENT] SERVER_HELLO received\n");

    /* -----------------------------------------------------
       X25519 SHARED SECRET
       ----------------------------------------------------- */

    printf(
        "[CLIENT] Deriving X25519 shared secret...\n");

    if (!derive_x25519_shared_secret(
            x25519_private_key,
            server_x25519_public_key,
            x25519_shared_secret))
    {
        goto cleanup;
    }

    printf(
        "[CLIENT] X25519 shared secret derived\n");

    /* -----------------------------------------------------
       ML-KEM DECAPSULATION
       ----------------------------------------------------- */

    printf(
        "[CLIENT] Decapsulating ML-KEM-768...\n");

    if (OQS_KEM_decaps(
            kem,
            mlkem_shared_secret,
            server_mlkem_ciphertext,
            mlkem_secret_key) != OQS_SUCCESS)
    {
        fprintf(
            stderr,
            "[CLIENT] ML-KEM-768 decapsulation failed\n");

        goto cleanup;
    }

    printf(
        "[CLIENT] ML-KEM-768 shared secret derived\n");

    /* -----------------------------------------------------
       HYBRID HKDF
       ----------------------------------------------------- */

    printf(
        "[CLIENT] Deriving hybrid session key...\n");

    if (!derive_hybrid_key(
            x25519_shared_secret,
            mlkem_shared_secret,
            hybrid_key))
    {
        goto cleanup;
    }

    printf(
        "[CLIENT] Hybrid session key derived\n");

    /* -----------------------------------------------------
       AES-256-GCM ENCRYPTION
       ----------------------------------------------------- */

    const unsigned char plaintext[] =
        PLAINTEXT;

    printf(
        "[CLIENT] Encrypting message...\n");

    ciphertext_length = aes_gcm_encrypt(
        plaintext,
        (int)strlen((const char *)plaintext),
        hybrid_key,
        nonce,
        ciphertext,
        tag);

    if (ciphertext_length <= 0)
    {
        fprintf(
            stderr,
            "[CLIENT] AES-256-GCM encryption failed\n");

        goto cleanup;
    }

    printf(
        "[CLIENT] AES-256-GCM encryption successful\n");

    /* -----------------------------------------------------
       BUILD ENCRYPTED MESSAGE
       ----------------------------------------------------- */

    unsigned char encrypted_payload[
        GCM_NONCE_SIZE +
        MAX_MESSAGE_SIZE +
        GCM_TAG_SIZE];

    uint32_t encrypted_payload_length =
        GCM_NONCE_SIZE +
        ciphertext_length +
        GCM_TAG_SIZE;

    memcpy(
        encrypted_payload,
        nonce,
        GCM_NONCE_SIZE);

    memcpy(
        encrypted_payload +
        GCM_NONCE_SIZE,
        ciphertext,
        ciphertext_length);

    memcpy(
        encrypted_payload +
        GCM_NONCE_SIZE +
        ciphertext_length,
        tag,
        GCM_TAG_SIZE);

    /* -----------------------------------------------------
       SEND ENCRYPTED MESSAGE
       ----------------------------------------------------- */

    printf(
        "[CLIENT] Sending encrypted message...\n");

    if (!send_packet(
            socket_fd,
            PACKET_ENCRYPTED_MESSAGE,
            encrypted_payload,
            encrypted_payload_length))
    {
        fprintf(
            stderr,
            "[CLIENT] Failed to send encrypted message\n");

        goto cleanup;
    }

    printf(
        "[CLIENT] Encrypted message sent\n");

    printf("\n");
    printf("========================================\n");
    printf(" HYBRID PQC CHANNEL TEST COMPLETE\n");
    printf("========================================\n");
    printf("X25519                  : SUCCESS\n");
    printf("ML-KEM-768             : SUCCESS\n");
    printf("HKDF-SHA-384           : SUCCESS\n");
    printf("AES-256-GCM encryption : SUCCESS\n");
    printf("Encrypted transmission : SUCCESS\n");
    printf("========================================\n\n");

    result = EXIT_SUCCESS;

cleanup:

    if (server_hello != NULL)
    {
        free(server_hello);
        server_hello = NULL;
    }

    if (socket_fd != INVALID_SOCKET)
    {
        closesocket(socket_fd);
        socket_fd = INVALID_SOCKET;
    }

    if (x25519_private_key != NULL)
    {
        EVP_PKEY_free(x25519_private_key);
        x25519_private_key = NULL;
    }

    if (kem != NULL)
    {
        OQS_KEM_free(kem);
        kem = NULL;
    }

    /*
     * Clear sensitive material before exiting.
     */
    SecureZeroMemory(
        mlkem_secret_key,
        sizeof(mlkem_secret_key));

    SecureZeroMemory(
        x25519_shared_secret,
        sizeof(x25519_shared_secret));

    SecureZeroMemory(
        mlkem_shared_secret,
        sizeof(mlkem_shared_secret));

    SecureZeroMemory(
        hybrid_key,
        sizeof(hybrid_key));

    SecureZeroMemory(
        ciphertext,
        sizeof(ciphertext));

    SecureZeroMemory(
        tag,
        sizeof(tag));

    SecureZeroMemory(
        nonce,
        sizeof(nonce));

    WSACleanup();

    return result;
}