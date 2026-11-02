#include <stdio.h>

#include "protocol_validation.h"
#include "constants.h"

int validate_icmp(const packet_t *packet, size_t offset, size_t payload_length, int more_fragments) {
    if (packet->captured_packet_length < offset + ICMP_HEADER_SIZE) {
        printf("ICMP: packet too small for header\n");
        return 0;
    }

    if (ICMP_HEADER_SIZE > payload_length && !more_fragments) {
        printf("ICMP: header exceeds IP payload\n");
        return 0;
    }

    return 1;
}

int validate_tcp(const packet_t *packet, size_t offset, size_t payload_length, int more_fragments) {

    (void)more_fragments;

    if (packet->captured_packet_length < offset + TCP_HEADER_MIN_SIZE) {
        printf("TCP: packet too small for header\n");
        return 0;
    }

    uint8_t data_offset =
        (packet->packet_data[offset + TCP_DATA_OFFSET] >>
        TCP_DATA_OFFSET_SHIFT) &
        TCP_DATA_OFFSET_MASK;

    if (data_offset < 5) {
        printf("TCP: invalid data_offset\n");
        return 0;
    }

    size_t tcp_header_length = data_offset * 4;

    if (tcp_header_length > payload_length) {
        printf("TCP: header exceeds IP payload\n");
        return 0;
    }

    if (packet->captured_packet_length < offset + tcp_header_length) {
        printf("TCP: packet too small for header length\n");
        return 0;
    }

    size_t options_offset =
        offset + TCP_HEADER_MIN_SIZE;

    size_t options_length =
        tcp_header_length - TCP_HEADER_MIN_SIZE;

    size_t options_position = 0;

    while (options_position < options_length) {
        uint8_t kind =
            packet->packet_data[options_offset + options_position];

        if (kind == 0) {
            break;
        }

        if (kind == 1) {
            options_position++;
            continue;
        }

        if (options_position + 1 >= options_length) {
            printf("TCP: option missing length\n");
            return 0;
        }

        uint8_t option_length =
            packet->packet_data[
                options_offset + options_position + 1
            ];

        if (option_length < 2) {
            printf("TCP: invalid option length\n");
            return 0;
        }

        if (options_position + option_length > options_length) {
            printf("TCP: option exceeds header\n");
            return 0;
        }

        options_position += option_length;
    }

    return 1;
}

int validate_udp(const packet_t *packet, size_t offset, size_t payload_length) {
    if (packet->captured_packet_length < offset + UDP_HEADER_SIZE) {
        printf("UDP: packet too small for header\n");
        return 0;
    }

    if (payload_length < UDP_HEADER_SIZE) {
        printf("UDP: IP payload too small for header\n");
        return 0;
    }

    uint16_t length =
        ((uint16_t)packet->packet_data[offset + UDP_LENGTH_OFFSET] << 8) |
        packet->packet_data[offset + UDP_LENGTH_OFFSET + 1];

    if (length < UDP_HEADER_SIZE) {
        printf("UDP: invalid length\n");
        return 0;
    }

    return 1;
}

int validate_protocol(const packet_t *packet, uint8_t protocol, size_t offset, size_t payload_length, int more_fragments) {
    if (packet == NULL || packet->packet_data == NULL) {
        return 0;
    }

    switch (protocol) {
    case IP_PROTOCOL_ICMP:
        return validate_icmp(packet, offset, payload_length, more_fragments);

    case IP_PROTOCOL_TCP:
        return validate_tcp(packet, offset, payload_length, more_fragments);

    case IP_PROTOCOL_UDP:
        return validate_udp(packet, offset, payload_length);

    default:
        printf("Protocol: unsupported protocol: %u\n", protocol);
        return 0;
    }
}