#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "protocol.h"

#define PORT 5555

#define X25519_SHARED_SECRET_SIZE 32
#define MLKEM_SHARED_SECRET_SIZE 32
#define HYBRID_KEY_SIZE 32

#define HKDF_INFO "HybridPQC-X25519-MLKEM768-AES256GCM"

#define AES_GCM_KEY_SIZE 32
#define AES_GCM_NONCE_SIZE 12
#define AES_GCM_TAG_SIZE 16


/* ============================================================
   OpenSSL error helper
   ============================================================ */

static void print_openssl_error(const char *message)
{
    fprintf(stderr, "[OpenSSL] %s\n", message);
    ERR_print_errors_fp(stderr);
}


/* ============================================================
   X25519 key generation
   ============================================================ */

static int generate_x25519_keypair(
    EVP_PKEY **private_key,
    unsigned char *public_key)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    size_t public_key_len = X25519_PUBLIC_KEY_SIZE;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (ctx == NULL)
    {
        print_openssl_error("EVP_PKEY_CTX_new_id failed");
        return 0;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        print_openssl_error("EVP_PKEY_keygen_init failed");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_keygen(ctx, &key) <= 0)
    {
        print_openssl_error("EVP_PKEY_keygen failed");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_get_raw_public_key(
            key,
            public_key,
            &public_key_len) <= 0)
    {
        print_openssl_error(
            "EVP_PKEY_get_raw_public_key failed");

        EVP_PKEY_free(key);
        EVP_PKEY_CTX_free(ctx);

        return 0;
    }

    *private_key = key;

    EVP_PKEY_CTX_free(ctx);

    return 1;
}


/* ============================================================
   X25519 shared secret
   ============================================================ */

static int derive_x25519_shared_secret(
    EVP_PKEY *private_key,
    const unsigned char *peer_public_key,
    unsigned char *shared_secret)
{
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    size_t shared_secret_len =
        X25519_SHARED_SECRET_SIZE;

    peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        NULL,
        peer_public_key,
        X25519_PUBLIC_KEY_SIZE);

    if (peer_key == NULL)
    {
        print_openssl_error(
            "EVP_PKEY_new_raw_public_key failed");

        return 0;
    }

    ctx = EVP_PKEY_CTX_new(private_key, NULL);

    if (ctx == NULL)
    {
        print_openssl_error(
            "EVP_PKEY_CTX_new failed");

        EVP_PKEY_free(peer_key);

        return 0;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        print_openssl_error(
            "EVP_PKEY_derive_init failed");

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);

        return 0;
    }

    /*
     * OpenSSL 3.x API.
     *
     * Do NOT use:
     *
     * EVP_PKEY_derive_set1_peer()
     *
     * because that symbol is not present in the
     * OpenSSL libraries installed on this system.
     */

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
            &shared_secret_len) <= 0)
    {
        print_openssl_error(
            "EVP_PKEY_derive failed");

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);

        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);

    return 1;
}


/* ============================================================
   Hybrid session key derivation

   X25519 secret
          +
   ML-KEM-768 secret
          |
          v
   HKDF-SHA-384
          |
          v
   32-byte AES-256 key
   ============================================================ */

static int derive_hybrid_session_key(
    const unsigned char *x25519_secret,
    const unsigned char *mlkem_secret,
    unsigned char *hybrid_key)
{
    unsigned char combined_secret[
        X25519_SHARED_SECRET_SIZE +
        MLKEM_SHARED_SECRET_SIZE
    ];

    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;

    int success = 0;

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
            "EVP_KDF_fetch failed");

        goto cleanup;
    }

    kdf_ctx = EVP_KDF_CTX_new(kdf);

    if (kdf_ctx == NULL)
    {
        print_openssl_error(
            "EVP_KDF_CTX_new failed");

        goto cleanup;
    }

    {
        const char *digest = "SHA384";

        const unsigned char info[] =
            HKDF_INFO;

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

            goto cleanup;
        }
    }

    success = 1;

cleanup:

    OPENSSL_cleanse(
        combined_secret,
        sizeof(combined_secret));

    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);

    return success;
}


/* ============================================================
   AES-256-GCM decryption
   ============================================================ */

static int aes_gcm_decrypt(
    const unsigned char *key,
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

    int success = 0;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
    {
        print_openssl_error(
            "EVP_CIPHER_CTX_new failed");

        return 0;
    }

    if (EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) <= 0)
    {
        print_openssl_error(
            "EVP_DecryptInit_ex failed");

        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            AES_GCM_NONCE_SIZE,
            NULL) <= 0)
    {
        print_openssl_error(
            "Setting GCM nonce length failed");

        goto cleanup;
    }

    if (EVP_DecryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce) <= 0)
    {
        print_openssl_error(
            "Setting AES key and nonce failed");

        goto cleanup;
    }

    if (EVP_DecryptUpdate(
            ctx,
            plaintext,
            &len,
            ciphertext,
            (int)ciphertext_len) <= 0)
    {
        print_openssl_error(
            "EVP_DecryptUpdate failed");

        goto cleanup;
    }

    *plaintext_len = (size_t)len;

    /*
     * Supply authentication tag before finalization.
     */

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            AES_GCM_TAG_SIZE,
            (void *)tag) <= 0)
    {
        print_openssl_error(
            "Setting GCM authentication tag failed");

        goto cleanup;
    }

    /*
     * This verifies authentication.
     *
     * If ciphertext or tag was modified,
     * EVP_DecryptFinal_ex() returns <= 0.
     */

    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext + len,
            &final_len) <= 0)
    {
        fprintf(
            stderr,
            "[AES-GCM] Authentication FAILED\n");

        goto cleanup;
    }

    *plaintext_len +=
        (size_t)final_len;

    success = 1;

cleanup:

    EVP_CIPHER_CTX_free(ctx);

    return success;
}


/* ============================================================
   Main server
   ============================================================ */

int main(void)
{
#ifdef _WIN32

    WSADATA wsa;

    if (WSAStartup(
            MAKEWORD(2, 2),
            &wsa) != 0)
    {
        fprintf(
            stderr,
            "WSAStartup failed\n");

        return 1;
    }

#endif

    SOCKET server_socket = INVALID_SOCKET;
    SOCKET client_socket = INVALID_SOCKET;

    struct sockaddr_in server_address;
    struct sockaddr_in client_address;

#ifdef _WIN32
    int client_address_length =
        sizeof(client_address);
#else
    socklen_t client_address_length =
        sizeof(client_address);
#endif

    EVP_PKEY *server_x25519_private = NULL;

    unsigned char server_x25519_public[
        X25519_PUBLIC_KEY_SIZE
    ];

    unsigned char x25519_shared_secret[
        X25519_SHARED_SECRET_SIZE
    ];

    unsigned char mlkem_shared_secret[
        MLKEM_SHARED_SECRET_SIZE
    ];

    unsigned char hybrid_key[
        HYBRID_KEY_SIZE
    ];

    unsigned char client_x25519_public[
        X25519_PUBLIC_KEY_SIZE
    ];

    unsigned char client_mlkem_public[
        MLKEM768_PUBLIC_KEY_SIZE
    ];

    unsigned char mlkem_ciphertext[
        MLKEM768_CIPHERTEXT_SIZE
    ];

    unsigned char server_hello[
        X25519_PUBLIC_KEY_SIZE +
        MLKEM768_CIPHERTEXT_SIZE
    ];

    OQS_KEM *kem = NULL;

    unsigned char *packet_payload = NULL;

    uint8_t packet_type = 0;

    uint32_t packet_length = 0;

    int result = 1;


    printf("\n");
    printf("========================================\n");
    printf(" Hybrid PQC Secure Server\n");
    printf(" X25519 + ML-KEM-768 + AES-256-GCM\n");
    printf("========================================\n");
    printf("\n");


    /* ========================================================
       Create TCP socket
       ======================================================== */

    server_socket = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP);

    if (server_socket == INVALID_SOCKET)
    {
        fprintf(
            stderr,
            "Failed to create server socket\n");

        goto cleanup;
    }


    /* ========================================================
       Allow address reuse
       ======================================================== */

    {
        int option = 1;

        if (setsockopt(
                server_socket,
                SOL_SOCKET,
                SO_REUSEADDR,
                (const char *)&option,
                sizeof(option)) < 0)
        {
            fprintf(
                stderr,
                "setsockopt failed\n");

            goto cleanup;
        }
    }


    /* ========================================================
       Server address
       ======================================================== */

    memset(
        &server_address,
        0,
        sizeof(server_address));

    server_address.sin_family =
        AF_INET;

    server_address.sin_addr.s_addr =
        htonl(INADDR_ANY);

    server_address.sin_port =
        htons(PORT);


    /* ========================================================
       Bind
       ======================================================== */

    if (bind(
            server_socket,
            (struct sockaddr *)&server_address,
            sizeof(server_address)) < 0)
    {
        fprintf(
            stderr,
            "Bind failed on port %d\n",
            PORT);

        goto cleanup;
    }


    /* ========================================================
       Listen
       ======================================================== */

    if (listen(
            server_socket,
            1) < 0)
    {
        fprintf(
            stderr,
            "Listen failed\n");

        goto cleanup;
    }


    printf(
        "[SERVER] Listening on port %d...\n",
        PORT);


    /* ========================================================
       Accept client
       ======================================================== */

    client_socket = accept(
        server_socket,
        (struct sockaddr *)&client_address,
        &client_address_length);

    if (client_socket == INVALID_SOCKET)
    {
        fprintf(
            stderr,
            "Accept failed\n");

        goto cleanup;
    }


    printf(
        "[SERVER] Client connected.\n");


    /* ========================================================
       Receive CLIENT_HELLO
       ======================================================== */

    if (!recv_packet(
            client_socket,
            &packet_type,
            &packet_payload,
            &packet_length))
    {
        fprintf(
            stderr,
            "[SERVER] Failed to receive CLIENT_HELLO\n");

        goto cleanup;
    }

    if (packet_type != PACKET_CLIENT_HELLO)
    {
        fprintf(
            stderr,
            "[SERVER] Expected CLIENT_HELLO, "
            "received packet type %u\n",
            packet_type);

        goto cleanup;
    }

    if (packet_length !=
        X25519_PUBLIC_KEY_SIZE +
        MLKEM768_PUBLIC_KEY_SIZE)
    {
        fprintf(
            stderr,
            "[SERVER] Invalid CLIENT_HELLO size: %u\n",
            packet_length);

        goto cleanup;
    }


    /* ========================================================
       Parse CLIENT_HELLO
       ======================================================== */

    memcpy(
        client_x25519_public,
        packet_payload,
        X25519_PUBLIC_KEY_SIZE);

    memcpy(
        client_mlkem_public,
        packet_payload +
        X25519_PUBLIC_KEY_SIZE,
        MLKEM768_PUBLIC_KEY_SIZE);

    free(packet_payload);
    packet_payload = NULL;

    printf(
        "[SERVER] CLIENT_HELLO received.\n");

    printf(
        "[SERVER] X25519 public key received.\n");

    printf(
        "[SERVER] ML-KEM-768 public key received.\n");


    /* ========================================================
       Generate server X25519 keypair
       ======================================================== */

    if (!generate_x25519_keypair(
            &server_x25519_private,
            server_x25519_public))
    {
        fprintf(
            stderr,
            "[SERVER] X25519 key generation failed.\n");

        goto cleanup;
    }

    printf(
        "[SERVER] X25519 keypair generated.\n");


    /* ========================================================
       X25519 key agreement
       ======================================================== */

    if (!derive_x25519_shared_secret(
            server_x25519_private,
            client_x25519_public,
            x25519_shared_secret))
    {
        fprintf(
            stderr,
            "[SERVER] X25519 shared secret failed.\n");

        goto cleanup;
    }

    printf(
        "[SERVER] X25519 shared secret established.\n");


    /* ========================================================
       Initialize ML-KEM-768
       ======================================================== */

    kem = OQS_KEM_new(
        OQS_KEM_alg_ml_kem_768);

    if (kem == NULL)
    {
        fprintf(
            stderr,
            "[SERVER] Failed to initialize ML-KEM-768.\n");

        goto cleanup;
    }

    if (kem->length_public_key !=
        MLKEM768_PUBLIC_KEY_SIZE)
    {
        fprintf(
            stderr,
            "[SERVER] Unexpected ML-KEM public key size.\n");

        goto cleanup;
    }

    if (kem->length_ciphertext !=
        MLKEM768_CIPHERTEXT_SIZE)
    {
        fprintf(
            stderr,
            "[SERVER] Unexpected ML-KEM ciphertext size.\n");

        goto cleanup;
    }

    if (kem->length_shared_secret !=
        MLKEM_SHARED_SECRET_SIZE)
    {
        fprintf(
            stderr,
            "[SERVER] Unexpected ML-KEM shared secret size.\n");

        goto cleanup;
    }


    /* ========================================================
       ML-KEM encapsulation
       ======================================================== */

    if (OQS_KEM_encaps(
            kem,
            mlkem_ciphertext,
            mlkem_shared_secret,
            client_mlkem_public) !=
        OQS_SUCCESS)
    {
        fprintf(
            stderr,
            "[SERVER] ML-KEM encapsulation failed.\n");

        goto cleanup;
    }

    printf(
        "[SERVER] ML-KEM-768 encapsulation successful.\n");


    /* ========================================================
       Derive hybrid session key
       ======================================================== */

    if (!derive_hybrid_session_key(
            x25519_shared_secret,
            mlkem_shared_secret,
            hybrid_key))
    {
        fprintf(
            stderr,
            "[SERVER] Hybrid key derivation failed.\n");

        goto cleanup;
    }

    printf(
        "[SERVER] Hybrid session key derived.\n");

    printf(
        "[SERVER] X25519 + ML-KEM-768 + HKDF-SHA-384 ready.\n");


    /* ========================================================
       Construct SERVER_HELLO

       SERVER_HELLO:

       32 bytes  -> X25519 public key
       1088 bytes -> ML-KEM-768 ciphertext
       ======================================================== */

    memcpy(
        server_hello,
        server_x25519_public,
        X25519_PUBLIC_KEY_SIZE);

    memcpy(
        server_hello +
        X25519_PUBLIC_KEY_SIZE,
        mlkem_ciphertext,
        MLKEM768_CIPHERTEXT_SIZE);


    /* ========================================================
       Send SERVER_HELLO
       ======================================================== */

    if (!send_packet(
            client_socket,
            PACKET_SERVER_HELLO,
            server_hello,
            sizeof(server_hello)))
    {
        fprintf(
            stderr,
            "[SERVER] Failed to send SERVER_HELLO.\n");

        goto cleanup;
    }

    printf(
        "[SERVER] SERVER_HELLO sent.\n");

    printf(
        "[SERVER] Waiting for encrypted message...\n");


    /* ========================================================
       Receive encrypted message
       ======================================================== */

    if (!recv_packet(
            client_socket,
            &packet_type,
            &packet_payload,
            &packet_length))
    {
        fprintf(
            stderr,
            "[SERVER] Failed to receive encrypted message.\n");

        goto cleanup;
    }

    if (packet_type !=
        PACKET_ENCRYPTED_MESSAGE)
    {
        fprintf(
            stderr,
            "[SERVER] Expected ENCRYPTED_MESSAGE, "
            "received type %u\n",
            packet_type);

        goto cleanup;
    }


    /* ========================================================
       Validate encrypted packet

       nonce       = 12 bytes
       ciphertext  = variable
       tag         = 16 bytes

       minimum = 12 + 1 + 16 = 29
       ======================================================== */

    if (packet_length <
        AES_GCM_NONCE_SIZE +
        AES_GCM_TAG_SIZE +
        1)
    {
        fprintf(
            stderr,
            "[SERVER] Encrypted packet too small.\n");

        goto cleanup;
    }


    {
        unsigned char *nonce =
            packet_payload;

        unsigned char *ciphertext =
            packet_payload +
            AES_GCM_NONCE_SIZE;

        size_t ciphertext_len =
            packet_length -
            AES_GCM_NONCE_SIZE -
            AES_GCM_TAG_SIZE;

        unsigned char *tag =
            packet_payload +
            AES_GCM_NONCE_SIZE +
            ciphertext_len;

        unsigned char *plaintext =
            (unsigned char *)malloc(
                ciphertext_len + 1);

        size_t plaintext_len = 0;

        if (plaintext == NULL)
        {
            fprintf(
                stderr,
                "[SERVER] Failed to allocate plaintext buffer.\n");

            goto cleanup;
        }

        memset(
            plaintext,
            0,
            ciphertext_len + 1);


        /* ====================================================
           AES-256-GCM authentication + decryption
           ==================================================== */

        if (!aes_gcm_decrypt(
                hybrid_key,
                nonce,
                ciphertext,
                ciphertext_len,
                tag,
                plaintext,
                &plaintext_len))
        {
            fprintf(
                stderr,
                "[SERVER] AES-256-GCM authentication failed.\n");

            OPENSSL_cleanse(
                plaintext,
                ciphertext_len + 1);

            free(plaintext);

            goto cleanup;
        }


        plaintext[plaintext_len] = '\0';


        printf("\n");
        printf(
            "========================================\n");
        printf(
            " SECURE MESSAGE RECEIVED\n");
        printf(
            "========================================\n");
        printf(
            "%s\n",
            plaintext);
        printf(
            "========================================\n");
        printf("\n");


        printf(
            "[SERVER] AES-256-GCM authentication: SUCCESS\n");
        printf(
            "[SERVER] AES-256-GCM decryption: SUCCESS\n");
        printf(
            "[SERVER] Message integrity: VERIFIED\n");
        printf(
            "[SERVER] Hybrid secure channel: ACTIVE\n");


        OPENSSL_cleanse(
            plaintext,
            ciphertext_len + 1);

        free(plaintext);
    }


    result = 0;


cleanup:

    if (packet_payload != NULL)
    {
        free(packet_payload);
        packet_payload = NULL;
    }


    /* ========================================================
       Clean sensitive material
       ======================================================== */

    OPENSSL_cleanse(
        x25519_shared_secret,
        sizeof(x25519_shared_secret));

    OPENSSL_cleanse(
        mlkem_shared_secret,
        sizeof(mlkem_shared_secret));

    OPENSSL_cleanse(
        hybrid_key,
        sizeof(hybrid_key));

    OPENSSL_cleanse(
        mlkem_ciphertext,
        sizeof(mlkem_ciphertext));


    EVP_PKEY_free(
        server_x25519_private);

    OQS_KEM_free(
        kem);


#ifdef _WIN32

    if (client_socket != INVALID_SOCKET)
    {
        closesocket(client_socket);
    }

    if (server_socket != INVALID_SOCKET)
    {
        closesocket(server_socket);
    }

    WSACleanup();

#else

    if (client_socket >= 0)
    {
        close(client_socket);
    }

    if (server_socket >= 0)
    {
        close(server_socket);
    }

#endif


    if (result == 0)
    {
        printf("\n");
        printf(
            "[SERVER] Session completed successfully.\n");
    }
    else
    {
        printf("\n");
        printf(
            "[SERVER] Session failed.\n");
    }


    return result;
}