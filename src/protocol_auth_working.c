#include "protocol_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/* ============================================================
   Internal Validation Helpers
   ============================================================ */

static int is_valid_packet_type(uint8_t type)
{
    return type == PACKET_CLIENT_HELLO ||
           type == PACKET_SERVER_HELLO ||
           type == PACKET_ENCRYPTED_MESSAGE;
}


static int is_valid_payload_length(uint8_t type, uint32_t length)
{
    switch (type)
    {
        case PACKET_CLIENT_HELLO:
            return length == CLIENT_HELLO_SIZE;

        case PACKET_SERVER_HELLO:
            return length == SERVER_HELLO_AUTH_SIZE;

        case PACKET_ENCRYPTED_MESSAGE:
            return length >= (GCM_NONCE_SIZE + GCM_TAG_SIZE + 1) &&
                   length <= MAX_MESSAGE_SIZE;

        default:
            return 0;
    }
}


/* ============================================================
   Send All
   ============================================================ */

int send_all(
    SOCKET socket_fd,
    const unsigned char *data,
    size_t length)
{
    size_t total_sent = 0;

    while (total_sent < length)
    {
        int chunk = send(
            socket_fd,
            (const char *)(data + total_sent),
            (int)(length - total_sent),
            0
        );

        if (chunk == SOCKET_ERROR)
        {
            return -1;
        }

        if (chunk == 0)
        {
            return -1;
        }

        total_sent += (size_t)chunk;
    }

    return 0;
}


/* ============================================================
   Receive All
   ============================================================ */

int recv_all(
    SOCKET socket_fd,
    unsigned char *data,
    size_t length)
{
    size_t total_received = 0;

    while (total_received < length)
    {
        int chunk = recv(
            socket_fd,
            (char *)(data + total_received),
            (int)(length - total_received),
            0
        );

        if (chunk == SOCKET_ERROR)
        {
            return -1;
        }

        if (chunk == 0)
        {
            return -1;
        }

        total_received += (size_t)chunk;
    }

    return 0;
}


/* ============================================================
   Send Authenticated Packet
   ============================================================ */

int send_auth_packet(
    SOCKET socket_fd,
    uint8_t type,
    const unsigned char *payload,
    uint32_t payload_length)
{
    AuthPacketHeader header;

    if (!is_valid_packet_type(type))
    {
        fprintf(stderr, "Invalid packet type: %u\n", type);
        return -1;
    }

    if (payload == NULL && payload_length > 0)
    {
        fprintf(stderr, "Invalid NULL payload\n");
        return -1;
    }

    if (!is_valid_payload_length(type, payload_length))
    {
        fprintf(
            stderr,
            "Invalid payload length %u for packet type %u\n",
            payload_length,
            type
        );

        return -1;
    }

    header.version = HYBRID_AUTH_PROTOCOL_VERSION;
    header.type = type;
    header.length = htonl(payload_length);

    if (send_all(
            socket_fd,
            (const unsigned char *)&header,
            sizeof(header)) != 0)
    {
        return -1;
    }

    if (payload_length > 0)
    {
        if (send_all(
                socket_fd,
                payload,
                payload_length) != 0)
        {
            return -1;
        }
    }

    return 0;
}


/* ============================================================
   Receive Authenticated Packet
   ============================================================ */

int recv_auth_packet(
    SOCKET socket_fd,
    uint8_t *type,
    unsigned char **payload,
    uint32_t *payload_length)
{
    AuthPacketHeader header;
    uint32_t network_length;
    uint32_t length;
    unsigned char *buffer = NULL;

    if (type == NULL ||
        payload == NULL ||
        payload_length == NULL)
    {
        return -1;
    }

    *payload = NULL;
    *payload_length = 0;

    /* --------------------------------------------------------
       Receive fixed-size packet header
       -------------------------------------------------------- */

    if (recv_all(
            socket_fd,
            (unsigned char *)&header,
            sizeof(header)) != 0)
    {
        fprintf(stderr, "Failed to receive packet header\n");
        return -1;
    }

    /* --------------------------------------------------------
       Validate protocol version
       -------------------------------------------------------- */

    if (header.version != HYBRID_AUTH_PROTOCOL_VERSION)
    {
        fprintf(
            stderr,
            "Unsupported protocol version: %u\n",
            header.version
        );

        return -1;
    }

    /* --------------------------------------------------------
       Validate packet type
       -------------------------------------------------------- */

    if (!is_valid_packet_type(header.type))
    {
        fprintf(
            stderr,
            "Invalid packet type: %u\n",
            header.type
        );

        return -1;
    }

    /* --------------------------------------------------------
       Convert payload length from network byte order
       -------------------------------------------------------- */

    memcpy(
        &network_length,
        &header.length,
        sizeof(network_length)
    );

    length = ntohl(network_length);

    /* --------------------------------------------------------
       Validate payload length
       -------------------------------------------------------- */

    if (!is_valid_payload_length(header.type, length))
    {
        fprintf(
            stderr,
            "Invalid payload length: %u for packet type %u\n",
            length,
            header.type
        );

        return -1;
    }

    /* --------------------------------------------------------
       Allocate payload
       -------------------------------------------------------- */

    buffer = (unsigned char *)malloc(length);

    if (buffer == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    /* --------------------------------------------------------
       Receive payload
       -------------------------------------------------------- */

    if (recv_all(
            socket_fd,
            buffer,
            length) != 0)
    {
        fprintf(stderr, "Failed to receive packet payload\n");

        free(buffer);
        return -1;
    }

    /* --------------------------------------------------------
       Return packet
       -------------------------------------------------------- */

    *type = header.type;
    *payload = buffer;
    *payload_length = length;

    return 0;
}