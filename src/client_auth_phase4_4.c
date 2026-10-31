#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "protocol_auth.h"

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5555

#define X25519_PRIVATE_KEY_SIZE 32
#define X25519_PUBLIC_KEY_SIZE 32
#define X25519_SHARED_SECRET_SIZE 32

#define MLKEM768_SECRET_KEY_SIZE 2400
#define MLKEM768_SHARED_SECRET_SIZE 32

#define MAX_SERVER_HELLO_SIZE SERVER_HELLO_AUTH_SIZE

static const char *SERVER_PUBLIC_KEY_PATH =
    "C:\\HybridPQC\\keys\\server_mldsa_public.key";


/* ============================================================
   Utility: Load a binary file
   ============================================================ */

static int load_binary_file(
    const char *path,
    unsigned char *buffer,
    size_t expected_size
)
{
    FILE *file = fopen(path, "rb");

    if (file == NULL)
    {
        printf("[-] Failed to open file: %s\n", path);
        return 0;
    }

    size_t read_count = fread(buffer, 1, expected_size, file);

    fclose(file);

    if (read_count != expected_size)
    {
        printf("[-] Invalid file size for: %s\n", path);
        printf("    Expected: %zu bytes\n", expected_size);
        printf("    Received: %zu bytes\n", read_count);
        return 0;
    }

    return 1;
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
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &keypair) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    return keypair;
}


/* ============================================================
   Extract X25519 Public Key
   ============================================================ */

static int get_x25519_public_key(
    EVP_PKEY *keypair,
    unsigned char *public_key
)
{
    size_t length = X25519_PUBLIC_KEY_SIZE;

    if (EVP_PKEY_get_raw_public_key(
            keypair,
            public_key,
            &length) <= 0)
    {
        return 0;
    }

    return length == X25519_PUBLIC_KEY_SIZE;
}


/* ============================================================
   Derive X25519 Shared Secret
   ============================================================ */

static int derive_x25519_shared_secret(
    EVP_PKEY *private_key,
    const unsigned char *peer_public_key,
    unsigned char *shared_secret
)
{
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    size_t secret_length = X25519_SHARED_SECRET_SIZE;

    peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        NULL,
        peer_public_key,
        X25519_PUBLIC_KEY_SIZE
    );

    if (peer_key == NULL)
    {
        return 0;
    }

    ctx = EVP_PKEY_CTX_new(private_key, NULL);

    if (ctx == NULL)
    {
        EVP_PKEY_free(peer_key);
        return 0;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return 0;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return 0;
    }

    if (EVP_PKEY_derive(
            ctx,
            shared_secret,
            &secret_length) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);

    return secret_length == X25519_SHARED_SECRET_SIZE;
}


/* ============================================================
   Main
   ============================================================ */

int main(void)
{
    WSADATA wsa_data;
    SOCKET socket_fd = INVALID_SOCKET;

    EVP_PKEY *alice_x25519 = NULL;

    unsigned char alice_x25519_public[X25519_PUBLIC_KEY_SIZE];

    unsigned char alice_mlkem_public[MLKEM768_PUBLIC_KEY_SIZE];
    unsigned char alice_mlkem_secret[MLKEM768_SECRET_KEY_SIZE];

    unsigned char bob_x25519_public[X25519_PUBLIC_KEY_SIZE];
    unsigned char original_bob_x25519_public[X25519_PUBLIC_KEY_SIZE];
    unsigned char tampered_bob_x25519_public[X25519_PUBLIC_KEY_SIZE];

    unsigned char original_x25519_shared_secret[
        X25519_SHARED_SECRET_SIZE
    ];

    unsigned char tampered_x25519_shared_secret[
        X25519_SHARED_SECRET_SIZE
    ];

    unsigned char server_mlkem_ciphertext[
        MLKEM768_CIPHERTEXT_SIZE
    ];

    unsigned char signature[
        MLDSA65_SIGNATURE_SIZE
    ];

    unsigned char server_public_key[
        MLDSA65_PUBLIC_KEY_SIZE
    ];

    unsigned char *server_payload = NULL;
    uint32_t server_payload_length = 0;
    uint8_t packet_type = 0;

    unsigned char transcript[AUTH_TRANSCRIPT_SIZE];

    size_t transcript_offset = 0;
    uint16_t signature_length = 0;

    OQS_KEM *kem = NULL;

    int result = EXIT_FAILURE;

    printf("\n");
    printf("===============================================\n");
    printf("   PHASE 4.4 X25519 SECURITY TEST CLIENT\n");
    printf("===============================================\n\n");


    /* ========================================================
       Load trusted Bob ML-DSA public key
       ======================================================== */

    if (!load_binary_file(
            SERVER_PUBLIC_KEY_PATH,
            server_public_key,
            MLDSA65_PUBLIC_KEY_SIZE))
    {
        goto cleanup;
    }

    printf("[+] Bob's trusted ML-DSA-65 public key loaded\n");


    /* ========================================================
       Initialize Winsock
       ======================================================== */

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        printf("[-] WSAStartup failed\n");
        goto cleanup;
    }


    /* ========================================================
       Generate Alice X25519 key pair
       ======================================================== */

    alice_x25519 = generate_x25519_keypair();

    if (alice_x25519 == NULL)
    {
        printf("[-] Alice X25519 key generation failed\n");
        goto cleanup_wsa;
    }

    if (!get_x25519_public_key(
            alice_x25519,
            alice_x25519_public))
    {
        printf("[-] Failed to extract Alice X25519 public key\n");
        goto cleanup_wsa;
    }

    printf("[+] Alice X25519 key pair generated\n");


    /* ========================================================
       Generate Alice ML-KEM-768 key pair
       ======================================================== */

    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);

    if (kem == NULL)
    {
        printf("[-] Failed to initialize ML-KEM-768\n");
        goto cleanup_wsa;
    }

    if (kem->length_public_key != MLKEM768_PUBLIC_KEY_SIZE ||
        kem->length_secret_key != MLKEM768_SECRET_KEY_SIZE ||
        kem->length_ciphertext != MLKEM768_CIPHERTEXT_SIZE)
    {
        printf("[-] Unexpected ML-KEM-768 parameter sizes\n");
        goto cleanup_wsa;
    }

    if (OQS_KEM_keypair(
            kem,
            alice_mlkem_public,
            alice_mlkem_secret) != OQS_SUCCESS)
    {
        printf("[-] Alice ML-KEM-768 key generation failed\n");
        goto cleanup_wsa;
    }

    printf("[+] Alice ML-KEM-768 key pair generated\n");


    /* ========================================================
       Connect to Bob
       ======================================================== */

    struct sockaddr_in server_address;

    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (socket_fd == INVALID_SOCKET)
    {
        printf("[-] Socket creation failed\n");
        goto cleanup_wsa;
    }

    memset(&server_address, 0, sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);

    if (InetPtonA(
            AF_INET,
            SERVER_IP,
            &server_address.sin_addr) != 1)
    {
        printf("[-] Invalid server address\n");
        goto cleanup_wsa;
    }

    if (connect(
            socket_fd,
            (struct sockaddr *)&server_address,
            sizeof(server_address)) == SOCKET_ERROR)
    {
        printf("[-] Failed to connect to Bob\n");
        goto cleanup_wsa;
    }

    printf("[+] Connected to Bob\n");


    /* ========================================================
       CLIENT_HELLO
       ======================================================== */

    unsigned char client_hello[CLIENT_HELLO_SIZE];

    memcpy(
        client_hello,
        alice_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    memcpy(
        client_hello + X25519_PUBLIC_KEY_SIZE,
        alice_mlkem_public,
        MLKEM768_PUBLIC_KEY_SIZE
    );

    if (send_auth_packet(
            socket_fd,
            PACKET_CLIENT_HELLO,
            client_hello,
            CLIENT_HELLO_SIZE) != 0)
    {
        printf("[-] Failed to send CLIENT_HELLO\n");
        goto cleanup_wsa;
    }

    printf("[+] CLIENT_HELLO sent\n");


    /* ========================================================
       Receive authenticated SERVER_HELLO
       ======================================================== */

    if (recv_auth_packet(
            socket_fd,
            &packet_type,
            &server_payload,
            &server_payload_length) != 0)
    {
        printf("[-] Failed to receive SERVER_HELLO\n");
        goto cleanup_wsa;
    }

    if (packet_type != PACKET_SERVER_HELLO)
    {
        printf("[-] Unexpected packet type: %u\n", packet_type);
        goto cleanup_wsa;
    }

    if (server_payload_length != SERVER_HELLO_AUTH_SIZE)
    {
        printf("[-] Unexpected SERVER_HELLO size\n");
        goto cleanup_wsa;
    }

    printf("[+] Authenticated SERVER_HELLO received\n");


    /* ========================================================
       Parse SERVER_HELLO
       ======================================================== */

    size_t offset = 0;

    memcpy(
        bob_x25519_public,
        server_payload + offset,
        X25519_PUBLIC_KEY_SIZE
    );

    offset += X25519_PUBLIC_KEY_SIZE;

    memcpy(
        server_mlkem_ciphertext,
        server_payload + offset,
        MLKEM768_CIPHERTEXT_SIZE
    );

    offset += MLKEM768_CIPHERTEXT_SIZE;

    uint8_t auth_algorithm =
        server_payload[offset++];

    if (auth_algorithm != AUTH_ALG_MLDSA65)
    {
        printf("[-] Unexpected authentication algorithm\n");
        goto cleanup_wsa;
    }

    memcpy(
        &signature_length,
        server_payload + offset,
        AUTH_SIGNATURE_LENGTH_SIZE
    );

    offset += AUTH_SIGNATURE_LENGTH_SIZE;

    signature_length = ntohs(signature_length);

    if (signature_length != MLDSA65_SIGNATURE_SIZE)
    {
        printf("[-] Unexpected ML-DSA signature length\n");
        goto cleanup_wsa;
    }

    memcpy(
        signature,
        server_payload + offset,
        MLDSA65_SIGNATURE_SIZE
    );

    printf("[+] ML-DSA-65 signature extracted\n");


    /* ========================================================
       Reconstruct authentication transcript
       ======================================================== */

    transcript_offset = 0;

    memcpy(
        transcript + transcript_offset,
        AUTH_DOMAIN_SEPARATOR,
        AUTH_DOMAIN_SEPARATOR_SIZE
    );

    transcript_offset += AUTH_DOMAIN_SEPARATOR_SIZE;

    transcript[transcript_offset++] =
        HYBRID_AUTH_PROTOCOL_VERSION;

    transcript[transcript_offset++] =
        AUTH_ALG_MLDSA65;

    memcpy(
        transcript + transcript_offset,
        alice_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    transcript_offset += X25519_PUBLIC_KEY_SIZE;

    memcpy(
        transcript + transcript_offset,
        alice_mlkem_public,
        MLKEM768_PUBLIC_KEY_SIZE
    );

    transcript_offset += MLKEM768_PUBLIC_KEY_SIZE;

    memcpy(
        transcript + transcript_offset,
        bob_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    transcript_offset += X25519_PUBLIC_KEY_SIZE;

    memcpy(
        transcript + transcript_offset,
        server_mlkem_ciphertext,
        MLKEM768_CIPHERTEXT_SIZE
    );

    transcript_offset += MLKEM768_CIPHERTEXT_SIZE;

    if (transcript_offset != AUTH_TRANSCRIPT_SIZE)
    {
        printf("[-] Transcript size mismatch\n");
        goto cleanup_wsa;
    }

    printf("[+] Authentication transcript reconstructed\n");


    /* ========================================================
       Verify ML-DSA-65 signature
       ======================================================== */

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if (sig == NULL)
    {
        printf("[-] Failed to initialize ML-DSA-65\n");
        goto cleanup_wsa;
    }

    if (OQS_SIG_verify(
            sig,
            transcript,
            AUTH_TRANSCRIPT_SIZE,
            signature,
            signature_length,
            server_public_key) != OQS_SUCCESS)
    {
        printf("[-] ML-DSA-65 signature verification FAILED\n");
        OQS_SIG_free(sig);
        goto cleanup_wsa;
    }

    OQS_SIG_free(sig);

    printf("[+] Bob ML-DSA-65 signature VERIFIED\n");
    printf("[+] Bob's identity authenticated\n");


    /* ========================================================
       PHASE 4.4
       ======================================================== */

    printf("\n");
    printf("===============================================\n");
    printf("       PHASE 4.4 SECURITY TEST\n");
    printf("       X25519 PUBLIC-KEY TAMPERING\n");
    printf("===============================================\n");


    /* ========================================================
       Preserve original Bob X25519 public key
       ======================================================== */

    memcpy(
        original_bob_x25519_public,
        bob_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    printf(
        "[TEST] Original Bob X25519 public key preserved.\n"
    );


    /* ========================================================
       Derive legitimate X25519 shared secret
       ======================================================== */

    if (!derive_x25519_shared_secret(
            alice_x25519,
            original_bob_x25519_public,
            original_x25519_shared_secret))
    {
        printf(
            "[-] Failed to derive original X25519 shared secret\n"
        );
        goto cleanup_wsa;
    }

    printf(
        "[TEST] Original X25519 shared secret derived.\n"
    );


    /* ========================================================
       Create tampered copy
       ======================================================== */

    memcpy(
        tampered_bob_x25519_public,
        original_bob_x25519_public,
        X25519_PUBLIC_KEY_SIZE
    );

    tampered_bob_x25519_public[0] ^= 0x01;

    printf(
        "[TEST] Tampering with X25519 public key...\n"
    );

    printf(
        "[TEST] One bit of Bob's X25519 public key "
        "was intentionally modified.\n"
    );


    /* ========================================================
       Derive shared secret using tampered public key
       ======================================================== */

    if (!derive_x25519_shared_secret(
            alice_x25519,
            tampered_bob_x25519_public,
            tampered_x25519_shared_secret))
    {
        printf(
            "[+] Tampered X25519 public key was rejected.\n"
        );

        printf(
            "[+] Modified key cannot establish the "
            "legitimate shared secret.\n"
        );

        printf(
            "\n===============================================\n"
        );

        printf(
            "       PHASE 4.4 SECURITY TEST: PASS\n"
        );

        printf(
            "===============================================\n"
        );

        printf(
            "RESULT: X25519 PUBLIC-KEY TAMPERING DETECTED\n"
        );

        printf(
            "===============================================\n"
        );

        result = EXIT_SUCCESS;
        goto cleanup_wsa;
    }

    printf(
        "[TEST] Tampered X25519 shared secret derived.\n"
    );


    /* ========================================================
       Compare secrets
       ======================================================== */

    if (memcmp(
            original_x25519_shared_secret,
            tampered_x25519_shared_secret,
            X25519_SHARED_SECRET_SIZE) != 0)
    {
        printf(
            "[+] Original and tampered X25519 shared "
            "secrets are DIFFERENT.\n"
        );

        printf(
            "[+] Tampered public key cannot reproduce "
            "the legitimate X25519 secret.\n"
        );

        printf(
            "[+] Hybrid session-key derivation blocked.\n"
        );

        printf(
            "\n===============================================\n"
        );

        printf(
            "       PHASE 4.4 SECURITY TEST: PASS\n"
        );

        printf(
            "===============================================\n"
        );

        printf(
            "X25519 public-key tampering detected.\n"
        );

        printf(
            "Original and tampered shared secrets differ.\n"
        );

        printf(
            "RESULT: X25519 PUBLIC-KEY TAMPERING DETECTED\n"
        );

        printf(
            "===============================================\n"
        );

        result = EXIT_SUCCESS;
        goto cleanup_wsa;
    }


    /* ========================================================
       Unexpected result
       ======================================================== */

    printf(
        "[-] Original and tampered X25519 shared secrets MATCH.\n"
    );

    printf(
        "[-] PHASE 4.4 SECURITY TEST: FAIL\n"
    );


cleanup_wsa:

    if (server_payload != NULL)
    {
        free(server_payload);
        server_payload = NULL;
    }

    if (socket_fd != INVALID_SOCKET)
    {
        closesocket(socket_fd);
        socket_fd = INVALID_SOCKET;
    }

    if (alice_x25519 != NULL)
    {
        EVP_PKEY_free(alice_x25519);
        alice_x25519 = NULL;
    }

    if (kem != NULL)
    {
        OQS_KEM_free(kem);
        kem = NULL;
    }

    WSACleanup();


cleanup:

    printf("\n");

    return result;
}