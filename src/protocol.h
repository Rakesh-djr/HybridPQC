#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32

#include <winsock2.h>

#else

#include <sys/socket.h>

#endif


/*
 * ============================================================
 * HYBRID PQC PROTOCOL
 * ============================================================
 *
 * Classical      : X25519
 * Post-Quantum   : ML-KEM-768
 * KDF            : HKDF-SHA-384
 * Encryption     : AES-256-GCM
 *
 * Protocol version: 1
 */


/*
 * ============================================================
 * PROTOCOL CONSTANTS
 * ============================================================
 */

#define HYBRID_PROTOCOL_VERSION 1


/*
 * X25519 public key
 *
 * X25519 public keys are exactly 32 bytes.
 */
#define X25519_PUBLIC_KEY_SIZE 32


/*
 * ML-KEM-768 sizes
 *
 * Public Key  : 1184 bytes
 * Ciphertext  : 1088 bytes
 */
#define MLKEM768_PUBLIC_KEY_SIZE 1184
#define MLKEM768_CIPHERTEXT_SIZE 1088


/*
 * AES-256-GCM
 *
 * Nonce : 12 bytes
 * Tag   : 16 bytes
 */
#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE   16


/*
 * Maximum packet payload.
 *
 * This prevents an attacker from forcing
 * unreasonable memory allocation.
 */
#define MAX_MESSAGE_SIZE 16384


/*
 * ============================================================
 * PACKET TYPES
 * ============================================================
 */

/*
 * Alice → Bob
 *
 * Contains Alice's public keys.
 */
#define PACKET_CLIENT_HELLO 1


/*
 * Bob → Alice
 *
 * Contains Bob's X25519 public key and
 * ML-KEM ciphertext.
 */
#define PACKET_SERVER_HELLO 2


/*
 * Reserved for future protocol expansion.
 */
#define PACKET_KEY_EXCHANGE 3


/*
 * Encrypted application data.
 *
 * Contains:
 *
 *     nonce
 *     ciphertext
 *     authentication tag
 */
#define PACKET_ENCRYPTED_MESSAGE 4


/*
 * ============================================================
 * CLIENT HELLO
 * ============================================================
 *
 * Alice sends:
 *
 *     X25519 public key       32 bytes
 *     ML-KEM-768 public key 1184 bytes
 *
 * Total:
 *
 *     32 + 1184 = 1216 bytes
 */
#pragma pack(push, 1)

typedef struct
{
    unsigned char x25519_public_key[
        X25519_PUBLIC_KEY_SIZE];

    unsigned char mlkem_public_key[
        MLKEM768_PUBLIC_KEY_SIZE];

} ClientHello;


/*
 * ============================================================
 * SERVER HELLO
 * ============================================================
 *
 * Bob sends:
 *
 *     X25519 public key       32 bytes
 *     ML-KEM ciphertext      1088 bytes
 *
 * Total:
 *
 *     32 + 1088 = 1120 bytes
 */
typedef struct
{
    unsigned char x25519_public_key[
        X25519_PUBLIC_KEY_SIZE];

    unsigned char mlkem_ciphertext[
        MLKEM768_CIPHERTEXT_SIZE];

} ServerHello;


/*
 * ============================================================
 * ENCRYPTED MESSAGE
 * ============================================================
 *
 * Bob receives:
 *
 *     GCM nonce
 *     ciphertext
 *     authentication tag
 *
 * The ciphertext size is variable because the
 * plaintext size is variable.
 *
 * Therefore we store only nonce + tag here,
 * while the ciphertext follows immediately.
 */
typedef struct
{
    unsigned char nonce[
        GCM_NONCE_SIZE];

    unsigned char tag[
        GCM_TAG_SIZE];

} EncryptedMessageHeader;

#pragma pack(pop)


/*
 * ============================================================
 * GENERIC PACKET HEADER
 * ============================================================
 *
 * Every TCP protocol packet starts with:
 *
 *     version  : 1 byte
 *     type     : 1 byte
 *     length   : 4 bytes
 *
 * The length field is stored in network byte order.
 */
#pragma pack(push, 1)

typedef struct
{
    uint8_t version;
    uint8_t type;
    uint32_t length;

} PacketHeader;

#pragma pack(pop)


/*
 * ============================================================
 * NETWORK FUNCTIONS
 * ============================================================
 */


/*
 * send_all()
 *
 * TCP send() may transmit fewer bytes than requested.
 *
 * This function keeps calling send() until
 * the complete buffer has been transmitted.
 *
 * Returns:
 *
 *     1 = success
 *     0 = failure
 */
int send_all(
    SOCKET socket_fd,
    const unsigned char *data,
    size_t length);


/*
 * recv_all()
 *
 * TCP recv() may return fewer bytes than requested.
 *
 * This function keeps receiving until the
 * requested number of bytes has arrived.
 *
 * Returns:
 *
 *     1 = success
 *     0 = failure
 */
int recv_all(
    SOCKET socket_fd,
    unsigned char *data,
    size_t length);


/*
 * send_packet()
 *
 * Sends:
 *
 *     PacketHeader
 *     +
 *     Payload
 */
int send_packet(
    SOCKET socket_fd,
    uint8_t type,
    const unsigned char *payload,
    uint32_t payload_length);


/*
 * recv_packet()
 *
 * Receives:
 *
 *     PacketHeader
 *     +
 *     Payload
 *
 * The payload is dynamically allocated.
 *
 * IMPORTANT:
 * Caller must free() the returned payload.
 */
int recv_packet(
    SOCKET socket_fd,
    uint8_t *type,
    unsigned char **payload,
    uint32_t *payload_length);


#endif