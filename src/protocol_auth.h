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

#if defined(PHASE6_CRYPTO_AGILITY)
#define HYBRID_AUTH_PROTOCOL_VERSION 2
#define AUTH_DOMAIN_SEPARATOR "HybridPQC-Authenticated-Handshake-v2"
#define PHASE6_PROFILE_ID_FIELD_SIZE 1
#else
#define HYBRID_AUTH_PROTOCOL_VERSION 1
#define AUTH_DOMAIN_SEPARATOR "HybridPQC-Authenticated-Handshake-v1"
#define PHASE6_PROFILE_ID_FIELD_SIZE 0
#endif


/* ============================================================
   Classical + Post-Quantum Cryptography Sizes
   ============================================================ */

/* X25519 */
#define X25519_PUBLIC_KEY_SIZE 32

/* Phase 6 KEM profile. Build client and server with the same profile. */
#if defined(PHASE6_KEM_ADAPTIVE)
#define PHASE6_KEM_ALGORITHM "runtime-selected"
#define PHASE6_KEM_PROFILE_ID 0
#define MLKEM_PUBLIC_KEY_SIZE 1568
#define MLKEM_SECRET_KEY_SIZE 3168
#define MLKEM_CIPHERTEXT_SIZE 1568
#elif defined(PHASE6_KEM_512)
#define PHASE6_KEM_ALGORITHM "ML-KEM-512"
#define PHASE6_KEM_PROFILE_ID 1
#define MLKEM_PUBLIC_KEY_SIZE 800
#define MLKEM_SECRET_KEY_SIZE 1632
#define MLKEM_CIPHERTEXT_SIZE 768
#elif defined(PHASE6_KEM_1024)
#define PHASE6_KEM_ALGORITHM "ML-KEM-1024"
#define PHASE6_KEM_PROFILE_ID 3
#define MLKEM_PUBLIC_KEY_SIZE 1568
#define MLKEM_SECRET_KEY_SIZE 3168
#define MLKEM_CIPHERTEXT_SIZE 1568
#else
#define PHASE6_KEM_ALGORITHM "ML-KEM-768"
#define PHASE6_KEM_PROFILE_ID 2
#define MLKEM_PUBLIC_KEY_SIZE 1184
#define MLKEM_SECRET_KEY_SIZE 2400
#define MLKEM_CIPHERTEXT_SIZE 1088
#endif

/* Compatibility constants used by the earlier fixed ML-KEM-768 examples. */
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
#define PACKET_REPLAY_RESULT      3
#define PACKET_ENCRYPTED_MESSAGE  4
#define REPLAY_RESULT_PAYLOAD_SIZE 49


/* ============================================================
   Packet Payload Sizes
   ============================================================ */

/*
 * CLIENT_HELLO:
 *
 * X25519 public key
 * +
 * KEM profile ID
 * ML-KEM public key
 */

#define CLIENT_HELLO_SIZE \
    (X25519_PUBLIC_KEY_SIZE + \
     PHASE6_PROFILE_ID_FIELD_SIZE + \
     MLKEM_PUBLIC_KEY_SIZE)


/*
 * SERVER_HELLO:
 *
 * X25519 public key
 * +
 * KEM profile ID
 * +
 * ML-KEM ciphertext
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
     PHASE6_PROFILE_ID_FIELD_SIZE + \
     MLKEM_CIPHERTEXT_SIZE + \
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

#define AUTH_DOMAIN_SEPARATOR_SIZE \
    (sizeof(AUTH_DOMAIN_SEPARATOR) - 1)


/*
 * The signature covers:
 *
 * Domain separator
 * Protocol version
 * Authentication algorithm
 * KEM profile ID
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
     PHASE6_PROFILE_ID_FIELD_SIZE + \
     X25519_PUBLIC_KEY_SIZE + \
     MLKEM_PUBLIC_KEY_SIZE + \
     X25519_PUBLIC_KEY_SIZE + \
     MLKEM_CIPHERTEXT_SIZE)

#define MLKEM_PUBLIC_KEY_MAX_SIZE 1568
#define MLKEM_SECRET_KEY_MAX_SIZE 3168
#define MLKEM_CIPHERTEXT_MAX_SIZE 1568
#define CLIENT_HELLO_MAX_SIZE \
    (X25519_PUBLIC_KEY_SIZE + 1 + MLKEM_PUBLIC_KEY_MAX_SIZE)
#define SERVER_HELLO_AUTH_MAX_SIZE \
    (X25519_PUBLIC_KEY_SIZE + 1 + MLKEM_CIPHERTEXT_MAX_SIZE + 1 + \
     AUTH_SIGNATURE_LENGTH_SIZE + MLDSA65_SIGNATURE_SIZE)
#define AUTH_TRANSCRIPT_MAX_SIZE \
    (AUTH_DOMAIN_SEPARATOR_SIZE + 3 + 2 * X25519_PUBLIC_KEY_SIZE + \
     MLKEM_PUBLIC_KEY_MAX_SIZE + MLKEM_CIPHERTEXT_MAX_SIZE)


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
