#ifndef PROTOCOL_AUTH_H
#define PROTOCOL_AUTH_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

/* ============================================================
   Protocol Version
   ============================================================ */

#define HYBRID_AUTH_PROTOCOL_VERSION 1


/* ============================================================
   Classical + Post-Quantum Cryptography Sizes
   ============================================================ */

/* X25519 */
#define X25519_PUBLIC_KEY_SIZE 32

/* ML-KEM-768 */
#define MLKEM768_PUBLIC_KEY_SIZE 1184
#define MLKEM768_CIPHERTEXT_SIZE 1088

/* ML-DSA-65 */
#define MLDSA65_PUBLIC_KEY_SIZE 1952
#define MLDSA65_SECRET_KEY_SIZE 4032
#define MLDSA65_SIGNATURE_SIZE 3309


/* ============================================================
   AES-256-GCM
   ============================================================ */

#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16


/* ============================================================
   Packet Limits
   ============================================================ */

#define MAX_MESSAGE_SIZE 16384


/* ============================================================
   Authentication Algorithm IDs
   ============================================================ */

/*
 * Authentication algorithm identifier.
 *
 * 1 = ML-DSA-65
 *
 * Keeping an explicit ID makes the protocol crypto-agile:
 * another signature algorithm can be added later without
 * redesigning the entire protocol.
 */

#define AUTH_ALG_MLDSA65 1


/* ============================================================
   Packet Types
   ============================================================ */

#define PACKET_CLIENT_HELLO       1
#define PACKET_SERVER_HELLO       2
#define PACKET_ENCRYPTED_MESSAGE  4


/* ============================================================
   Packet Payload Sizes
   ============================================================ */

/*
 * CLIENT_HELLO:
 *
 * X25519 public key
 * +
 * ML-KEM-768 public key
 */

#define CLIENT_HELLO_SIZE \
    (X25519_PUBLIC_KEY_SIZE + MLKEM768_PUBLIC_KEY_SIZE)


/*
 * SERVER_HELLO:
 *
 * X25519 public key
 * +
 * ML-KEM-768 ciphertext
 * +
 * authentication algorithm ID
 * +
 * signature length
 * +
 * ML-DSA-65 signature
 *
 * Signature length uses uint16_t = 2 bytes.
 */

#define AUTH_SIGNATURE_LENGTH_SIZE 2

#define SERVER_HELLO_AUTH_SIZE \
    (X25519_PUBLIC_KEY_SIZE + \
     MLKEM768_CIPHERTEXT_SIZE + \
     1 + \
     AUTH_SIGNATURE_LENGTH_SIZE + \
     MLDSA65_SIGNATURE_SIZE)


/* ============================================================
   Authentication Transcript
   ============================================================ */

/*
 * Domain separator prevents this signature from being
 * accidentally interpreted as a signature for another
 * protocol or message type.
 */

#define AUTH_DOMAIN_SEPARATOR \
    "HybridPQC-Authenticated-Handshake-v1"

#define AUTH_DOMAIN_SEPARATOR_SIZE \
    (sizeof(AUTH_DOMAIN_SEPARATOR) - 1)


/*
 * The signature covers:
 *
 * Domain separator
 * Protocol version
 * Authentication algorithm
 * CLIENT_HELLO:
 *   - Alice X25519 public key
 *   - Alice ML-KEM public key
 * SERVER_HELLO:
 *   - Bob X25519 public key
 *   - ML-KEM ciphertext
 *
 * This binds the signature to the actual handshake.
 */

#define AUTH_TRANSCRIPT_SIZE \
    (AUTH_DOMAIN_SEPARATOR_SIZE + \
     1 + \
     1 + \
     X25519_PUBLIC_KEY_SIZE + \
     MLKEM768_PUBLIC_KEY_SIZE + \
     X25519_PUBLIC_KEY_SIZE + \
     MLKEM768_CIPHERTEXT_SIZE)


/* ============================================================
   Packet Header
   ============================================================ */

#pragma pack(push, 1)

typedef struct
{
    uint8_t version;
    uint8_t type;
    uint32_t length;
} AuthPacketHeader;

#pragma pack(pop)


/* ============================================================
   Network Functions
   ============================================================ */

int send_all(
    SOCKET socket_fd,
    const unsigned char *data,
    size_t length
);

int recv_all(
    SOCKET socket_fd,
    unsigned char *data,
    size_t length
);

int send_auth_packet(
    SOCKET socket_fd,
    uint8_t type,
    const unsigned char *payload,
    uint32_t payload_length
);

int recv_auth_packet(
    SOCKET socket_fd,
    uint8_t *type,
    unsigned char **payload,
    uint32_t *payload_length
);


/* ============================================================
   End of Header
   ============================================================ */

#endif /* PROTOCOL_AUTH_H */