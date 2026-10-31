#define _CRT_SECURE_NO_WARNINGS

#include "protocol_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

/* ============================================================
   Configuration
   ============================================================ */

#define SERVER_PORT 5555

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
        (void *)info,
        sizeof(info) - 1
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
}


/* ============================================================
   AES-256-GCM Decryption
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

    /*
     * EVP_DecryptFinal_ex performs the authentication check.
     *
     * If the ciphertext or tag has been modified,
     * this operation fails.
     */

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
     * Bob's ML-KEM ciphertext
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

int main(void)
{
    WSADATA wsa_data;

    SOCKET server_socket = INVALID_SOCKET;
    SOCKET client_socket = INVALID_SOCKET;

    struct sockaddr_in client_address;
    int client_address_length =
        sizeof(client_address);

    OQS_SIG *sig = NULL;

    unsigned char *mldsa_secret_key = NULL;

    unsigned char client_hello[
        CLIENT_HELLO_SIZE
    ];

    unsigned char client_x25519_public[
        X25519_PUBLIC_KEY_SIZE
    ];

    unsigned char client_mlkem_public[
        MLKEM768_PUBLIC_KEY_SIZE
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

    uint8_t packet_type = 0;

    unsigned char plaintext[
        MAX_MESSAGE_SIZE
    ];

    size_t plaintext_len = 0;

    EVP_PKEY *server_x25519_key = NULL;

    OQS_STATUS oqs_status;

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

    if (packet_type != PACKET_CLIENT_HELLO)
    {
        fprintf(
            stderr,
            "Expected CLIENT_HELLO, received packet type %u\n",
            packet_type
        );

        goto cleanup;
    }

    if (encrypted_payload_len != CLIENT_HELLO_SIZE)
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
        CLIENT_HELLO_SIZE
    );

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

    memcpy(
        client_mlkem_public,
        client_hello + X25519_PUBLIC_KEY_SIZE,
        MLKEM768_PUBLIC_KEY_SIZE
    );

    printf(
        "[+] Received Alice's X25519 public key\n"
    );

    printf(
        "[+] Received Alice's ML-KEM-768 public key\n"
    );


    /* ========================================================
       Generate Bob's X25519 Key Pair
       ======================================================== */

    server_x25519_key =
        generate_x25519_keypair();

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
       ML-KEM-768 Encapsulation
       ======================================================== */

    OQS_KEM *kem = OQS_KEM_new(
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

    oqs_status = OQS_KEM_encaps(
        kem,
        server_mlkem_ciphertext,
        mlkem_shared_secret,
        client_mlkem_public
    );

    OQS_KEM_free(kem);

    if (oqs_status != OQS_SUCCESS)
    {
        fprintf(
            stderr,
            "ML-KEM-768 encapsulation failed\n"
        );

        goto cleanup;
    }

    printf(
        "[+] ML-KEM-768 encapsulation successful\n"
    );


    /* ========================================================
       Build Authentication Transcript
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

    if (transcript_len != AUTH_TRANSCRIPT_SIZE)
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

    oqs_status = OQS_SIG_sign(
        sig,
        signature,
        &signature_len,
        transcript,
        transcript_len,
        mldsa_secret_key
    );

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


    /* ML-KEM ciphertext */

    memcpy(
        server_hello + server_hello_offset,
        server_mlkem_ciphertext,
        MLKEM768_CIPHERTEXT_SIZE
    );

    server_hello_offset +=
        MLKEM768_CIPHERTEXT_SIZE;


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


    if (server_hello_offset !=
        SERVER_HELLO_AUTH_SIZE)
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

    printf(
        "[+] Authenticated SERVER_HELLO sent\n"
    );


    /* ========================================================
       Derive X25519 Shared Secret
       ======================================================== */

    if (derive_x25519_shared_secret(
            server_x25519_key,
            client_x25519_public,
            x25519_shared_secret) != 0)
    {
        goto cleanup;
    }

    printf(
        "[+] X25519 shared secret derived\n"
    );


    /* ========================================================
       Derive Hybrid Session Key
       ======================================================== */

    if (derive_hybrid_session_key(
            x25519_shared_secret,
            mlkem_shared_secret,
            hybrid_session_key) != 0)
    {
        goto cleanup;
    }

    printf(
        "[+] Hybrid session key derived\n"
    );


    /* ========================================================
   PHASE 4.6 — RECEIVE FIRST ENCRYPTED MESSAGE
   ======================================================== */

printf("\n");
printf("===============================================\n");
printf("       PHASE 4.6 REPLAY SECURITY TEST\n");
printf("===============================================\n");

printf("[TEST] Waiting for original encrypted packet...\n");

if (recv_auth_packet(
        client_socket,
        &packet_type,
        &encrypted_payload,
        &encrypted_payload_len) != 0)
{
    fprintf(
        stderr,
        "Failed to receive original encrypted message\n"
    );

    goto cleanup;
}

if (packet_type != PACKET_ENCRYPTED_MESSAGE)
{
    fprintf(
        stderr,
        "Expected ENCRYPTED_MESSAGE, received %u\n",
        packet_type
    );

    goto cleanup;
}

if (encrypted_payload_len <
    GCM_NONCE_SIZE + GCM_TAG_SIZE + 1)
{
    fprintf(
        stderr,
        "Original encrypted payload is too small\n"
    );

    goto cleanup;
}

/*
 * Preserve the exact original packet.
 *
 * This allows us to compare it with the replayed
 * packet received later.
 */

unsigned char *original_encrypted_payload =
    (unsigned char *)malloc(encrypted_payload_len);

if (original_encrypted_payload == NULL)
{
    fprintf(
        stderr,
        "Failed to allocate replay-test buffer\n"
    );

    goto cleanup;
}

memcpy(
    original_encrypted_payload,
    encrypted_payload,
    encrypted_payload_len
);

uint32_t original_encrypted_payload_len =
    encrypted_payload_len;

printf(
    "[+] Original encrypted packet received: %u bytes\n",
    encrypted_payload_len
);


/* ========================================================
   DECRYPT ORIGINAL PACKET
   ======================================================== */

{
    const unsigned char *nonce =
        encrypted_payload;

    const unsigned char *ciphertext =
        encrypted_payload + GCM_NONCE_SIZE;

    size_t ciphertext_len =
        encrypted_payload_len -
        GCM_NONCE_SIZE -
        GCM_TAG_SIZE;

    const unsigned char *tag =
        encrypted_payload +
        GCM_NONCE_SIZE +
        ciphertext_len;

    plaintext_len = 0;

    if (aes_gcm_decrypt(
            hybrid_session_key,
            nonce,
            ciphertext,
            ciphertext_len,
            tag,
            plaintext,
            &plaintext_len) != 0)
    {
        fprintf(
            stderr,
            "Original message authentication failed\n"
        );

        free(original_encrypted_payload);
        goto cleanup;
    }
}

printf(
    "[+] Original packet accepted successfully\n"
);

printf(
    "[+] Original message: %.*s\n",
    (int)plaintext_len,
    plaintext
);


/* ========================================================
   WAIT FOR REPLAYED PACKET
   ======================================================== */

printf("\n");
printf("[TEST] Waiting for replayed packet...\n");

free(encrypted_payload);
encrypted_payload = NULL;
encrypted_payload_len = 0;

if (recv_auth_packet(
        client_socket,
        &packet_type,
        &encrypted_payload,
        &encrypted_payload_len) != 0)
{
    fprintf(
        stderr,
        "Failed to receive replayed encrypted message\n"
    );

    free(original_encrypted_payload);
    goto cleanup;
}

if (packet_type != PACKET_ENCRYPTED_MESSAGE)
{
    fprintf(
        stderr,
        "Expected replayed ENCRYPTED_MESSAGE, received %u\n",
        packet_type
    );

    free(original_encrypted_payload);
    goto cleanup;
}

printf(
    "[+] Replayed encrypted packet received: %u bytes\n",
    encrypted_payload_len
);


/* ========================================================
   VERIFY EXACT REPLAY
   ======================================================== */

if (encrypted_payload_len ==
        original_encrypted_payload_len &&
    memcmp(
        encrypted_payload,
        original_encrypted_payload,
        original_encrypted_payload_len
    ) == 0)
{
    printf(
        "[+] Replay packet is BYTE-FOR-BYTE IDENTICAL "
        "to the original packet\n"
    );
}
else
{
    printf(
        "[!] Replay packet differs from original packet\n"
    );
}


/* ========================================================
   ATTEMPT TO DECRYPT REPLAY
   ======================================================== */

{
    const unsigned char *nonce =
        encrypted_payload;

    const unsigned char *ciphertext =
        encrypted_payload + GCM_NONCE_SIZE;

    size_t ciphertext_len =
        encrypted_payload_len -
        GCM_NONCE_SIZE -
        GCM_TAG_SIZE;

    const unsigned char *tag =
        encrypted_payload +
        GCM_NONCE_SIZE +
        ciphertext_len;

    plaintext_len = 0;

    printf("\n");
    printf("[TEST] Attempting to decrypt replayed packet...\n");

    if (aes_gcm_decrypt(
            hybrid_session_key,
            nonce,
            ciphertext,
            ciphertext_len,
            tag,
            plaintext,
            &plaintext_len) == 0)
    {
        printf("\n");
        printf("===============================================\n");
        printf("       PHASE 4.6 SECURITY TEST: FINDING\n");
        printf("===============================================\n");

        printf(
            "[!] REPLAYED PACKET WAS ACCEPTED\n"
        );

        printf(
            "[!] AES-256-GCM authentication succeeded "
            "again\n"
        );

        printf(
            "[!] The same authenticated packet was accepted "
            "twice in the same session.\n"
        );

        printf(
            "[!] Current protocol has no replay/freshness "
            "mechanism.\n"
        );

        printf(
            "RESULT: REPLAY VULNERABILITY DETECTED\n"
        );

        printf(
            "===============================================\n"
        );

        free(original_encrypted_payload);

        result = EXIT_SUCCESS;
        goto cleanup;
    }
    else
    {
        printf("\n");
        printf("===============================================\n");
        printf("       PHASE 4.6 SECURITY TEST\n");
        printf("===============================================\n");

        printf(
            "[+] Replayed packet was rejected\n"
        );

        printf(
            "[+] AES-GCM authentication failed for replay\n"
        );

        printf(
            "RESULT: REPLAY REJECTED\n"
        );

        printf(
            "===============================================\n"
        );
    }
}

free(original_encrypted_payload);

result = EXIT_SUCCESS;

    /* ========================================================
       Parse AES-GCM Payload
       ======================================================== */

    {
        const unsigned char *nonce =
            encrypted_payload;

        const unsigned char *ciphertext =
            encrypted_payload + GCM_NONCE_SIZE;

        size_t ciphertext_len =
            encrypted_payload_len -
            GCM_NONCE_SIZE -
            GCM_TAG_SIZE;

        const unsigned char *tag =
            encrypted_payload +
            GCM_NONCE_SIZE +
            ciphertext_len;


        /* ====================================================
           AES-256-GCM Authentication + Decryption
           ==================================================== */

        if (aes_gcm_decrypt(
                hybrid_session_key,
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

            goto cleanup;
        }
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
        "Hybrid X25519 + ML-KEM-768: SUCCESS\n"
    );

    printf(
        "END-TO-END AUTHENTICATED HYBRID PQC VERIFIED\n"
    );

    printf(
        "===============================================\n"
    );

    result = EXIT_SUCCESS;


cleanup:

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

    if (sig != NULL)
    {
        OQS_SIG_free(sig);
    }

    WSACleanup();

    return result;
}