#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#include <winsock2.h>

#else

#include <arpa/inet.h>
#include <unistd.h>

#endif


/*
 * ============================================================
 * send_all()
 * ============================================================
 *
 * TCP send() is allowed to send fewer bytes than requested.
 *
 * This function keeps sending until the complete buffer
 * has been transmitted.
 */
int send_all(
    SOCKET socket_fd,
    const unsigned char *data,
    size_t length)
{
    size_t total_sent = 0;

    while (total_sent < length)
    {
        int sent = send(
            socket_fd,
            (const char *)(data + total_sent),
            (int)(length - total_sent),
            0);

        if (sent <= 0)
        {
            return 0;
        }

        total_sent += (size_t)sent;
    }

    return 1;
}


/*
 * ============================================================
 * recv_all()
 * ============================================================
 *
 * TCP recv() may return fewer bytes than requested.
 *
 * Keep receiving until the complete buffer arrives.
 */
int recv_all(
    SOCKET socket_fd,
    unsigned char *data,
    size_t length)
{
    size_t total_received = 0;

    while (total_received < length)
    {
        int received = recv(
            socket_fd,
            (char *)(data + total_received),
            (int)(length - total_received),
            0);

        if (received <= 0)
        {
            return 0;
        }

        total_received += (size_t)received;
    }

    return 1;
}


/*
 * ============================================================
 * is_valid_packet_type()
 * ============================================================
 *
 * Checks whether a packet type is one of the packet types
 * supported by our protocol.
 */
static int is_valid_packet_type(uint8_t type)
{
    switch (type)
    {
        case PACKET_CLIENT_HELLO:
        case PACKET_SERVER_HELLO:
        case PACKET_KEY_EXCHANGE:
        case PACKET_ENCRYPTED_MESSAGE:

            return 1;

        default:

            return 0;
    }
}


/*
 * ============================================================
 * is_valid_payload_length()
 * ============================================================
 *
 * Verifies that the payload size matches the expected
 * packet type.
 *
 * This prevents malformed packets from being accepted.
 */
static int is_valid_payload_length(
    uint8_t type,
    uint32_t length)
{
    switch (type)
    {
        /*
         * Alice → Bob
         *
         * X25519 public key
         * +
         * ML-KEM-768 public key
         */
        case PACKET_CLIENT_HELLO:

            return length ==
                (X25519_PUBLIC_KEY_SIZE +
                 MLKEM768_PUBLIC_KEY_SIZE);


        /*
         * Bob → Alice
         *
         * X25519 public key
         * +
         * ML-KEM-768 ciphertext
         */
        case PACKET_SERVER_HELLO:

            return length ==
                (X25519_PUBLIC_KEY_SIZE +
                 MLKEM768_CIPHERTEXT_SIZE);


        /*
         * Reserved packet.
         *
         * We currently don't use it.
         */
        case PACKET_KEY_EXCHANGE:

            return length > 0 &&
                   length <= MAX_MESSAGE_SIZE;


        /*
         * Encrypted message.
         *
         * Minimum payload:
         *
         *     nonce       = 12 bytes
         *     tag         = 16 bytes
         *
         * Ciphertext must contain at least one byte.
         */
        case PACKET_ENCRYPTED_MESSAGE:

            return length >=
                (GCM_NONCE_SIZE +
                 GCM_TAG_SIZE +
                 1)
                &&
                length <= MAX_MESSAGE_SIZE;


        default:

            return 0;
    }
}


/*
 * ============================================================
 * send_packet()
 * ============================================================
 *
 * Creates:
 *
 * +----------------------+
 * | Packet Header        |
 * +----------------------+
 * | Payload              |
 * +----------------------+
 */
int send_packet(
    SOCKET socket_fd,
    uint8_t type,
    const unsigned char *payload,
    uint32_t payload_length)
{
    /*
     * Validate packet type.
     */
    if (!is_valid_packet_type(type))
    {
        printf(
            "ERROR: Invalid packet type: %u\n",
            type);

        return 0;
    }


    /*
     * Validate payload length.
     */
    if (!is_valid_payload_length(
            type,
            payload_length))
    {
        printf(
            "ERROR: Invalid payload length: %u bytes "
            "for packet type %u\n",
            payload_length,
            type);

        return 0;
    }


    /*
     * Payload must not be NULL when
     * payload_length is greater than zero.
     */
    if (payload_length > 0 &&
        payload == NULL)
    {
        printf(
            "ERROR: NULL payload.\n");

        return 0;
    }


    PacketHeader header;


    /*
     * Protocol version.
     */
    header.version =
        HYBRID_PROTOCOL_VERSION;


    /*
     * Packet type.
     */
    header.type =
        type;


    /*
     * TCP/network byte order.
     */
    header.length =
        htonl(payload_length);


    /*
     * Send packet header.
     */
    if (!send_all(
            socket_fd,
            (const unsigned char *)&header,
            sizeof(header)))
    {
        printf(
            "ERROR: Failed to send packet header.\n");

        return 0;
    }


    /*
     * Send payload.
     */
    if (payload_length > 0)
    {
        if (!send_all(
                socket_fd,
                payload,
                payload_length))
        {
            printf(
                "ERROR: Failed to send packet payload.\n");

            return 0;
        }
    }


    return 1;
}


/*
 * ============================================================
 * recv_packet()
 * ============================================================
 *
 * Receives a complete framed packet.
 */
int recv_packet(
    SOCKET socket_fd,
    uint8_t *type,
    unsigned char **payload,
    uint32_t *payload_length)
{
    /*
     * Validate output pointers.
     */
    if (type == NULL ||
        payload == NULL ||
        payload_length == NULL)
    {
        printf(
            "ERROR: Invalid recv_packet arguments.\n");

        return 0;
    }


    /*
     * Initialize output values.
     */
    *type = 0;
    *payload = NULL;
    *payload_length = 0;


    PacketHeader header;


    /*
     * Receive packet header.
     */
    if (!recv_all(
            socket_fd,
            (unsigned char *)&header,
            sizeof(header)))
    {
        printf(
            "ERROR: Failed to receive packet header.\n");

        return 0;
    }


    /*
     * Verify protocol version.
     */
    if (header.version !=
        HYBRID_PROTOCOL_VERSION)
    {
        printf(
            "ERROR: Unsupported protocol version: %u\n",
            header.version);

        return 0;
    }


    /*
     * Verify packet type.
     */
    if (!is_valid_packet_type(
            header.type))
    {
        printf(
            "ERROR: Unknown packet type: %u\n",
            header.type);

        return 0;
    }


    /*
     * Convert length from network byte order.
     */
    uint32_t length =
        ntohl(header.length);


    /*
     * Prevent unreasonable allocation.
     */
    if (length > MAX_MESSAGE_SIZE)
    {
        printf(
            "ERROR: Packet too large: %u bytes\n",
            length);

        return 0;
    }


    /*
     * Verify the expected size for the packet.
     */
    if (!is_valid_payload_length(
            header.type,
            length))
    {
        printf(
            "ERROR: Invalid payload size %u bytes "
            "for packet type %u\n",
            length,
            header.type);

        return 0;
    }


    /*
     * Allocate payload buffer.
     */
    unsigned char *buffer =
        (unsigned char *)malloc(length);


    if (buffer == NULL)
    {
        printf(
            "ERROR: Memory allocation failed.\n");

        return 0;
    }


    /*
     * Receive complete payload.
     */
    if (!recv_all(
            socket_fd,
            buffer,
            length))
    {
        printf(
            "ERROR: Failed to receive packet payload.\n");

        free(buffer);

        return 0;
    }


    /*
     * Return packet information.
     */
    *type =
        header.type;

    *payload =
        buffer;

    *payload_length =
        length;


    return 1;
}