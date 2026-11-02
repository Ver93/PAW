#include <stdio.h>

#include "packet_validation.h"
#include "pcapng.h"
#include "constants.h"

static int validate_ipv4(const packet_t *packet) {
    size_t ip_offset = ETHERNET_HEADER_SIZE;

    if (packet->captured_packet_length < ip_offset + IPV4_HEADER_SIZE) {
        printf("Packet validation failed: packet too small for IPv4 header\n");
        return 1;
    }

    uint8_t version =
        packet->packet_data[ip_offset + IPV4_VERSION_OFFSET] >>
        IPV4_VERSION_SHIFT;

    if (version != 4) {
        printf("Packet validation failed: invalid IPv4 version: %u\n", version);
        return 1;
    }

    uint8_t ihl =
        packet->packet_data[ip_offset + IPV4_VERSION_OFFSET] &
        IPV4_IHL_MASK;

    if (ihl < 5) {
        printf("Packet validation failed: invalid IPv4 IHL: %u\n", ihl);
        return 1;
    }

    size_t ipv4_header_length = ihl * 4;

    if (packet->captured_packet_length < ip_offset + ipv4_header_length) {
        printf("Packet validation failed: packet too small for IPv4 header length\n");
        return 1;
    }

    uint16_t total_length =
        ((uint16_t)packet->packet_data[ip_offset + IPV4_TOTAL_LENGTH_OFFSET] << 8) |
        packet->packet_data[ip_offset + IPV4_TOTAL_LENGTH_OFFSET + 1];

    if (total_length < ipv4_header_length) {
        printf("Packet validation failed: invalid IPv4 total length: %u\n", total_length);
        return 1;
    }

    if (total_length > packet->captured_packet_length - ip_offset) {
        printf("Packet validation failed: IPv4 total length exceeds packet length\n");
        return 1;
    }

    uint16_t flags_fragment_offset =
        ((uint16_t)packet->packet_data[ip_offset + IPV4_FLAGS_OFFSET] << 8) |
        packet->packet_data[ip_offset + IPV4_FLAGS_OFFSET + 1];

    int more_fragments =
        (flags_fragment_offset & IPV4_MORE_FRAGMENTS_FLAG) != 0;

    size_t payload_length = total_length - ipv4_header_length;

    if (more_fragments && payload_length % IPV4_FRAGMENT_ALIGNMENT != 0) {
        printf("Packet validation failed: non-final IPv4 fragment payload is not 8-byte aligned\n");
        return 1;
    }

    return 0;
}

static int validate_ipv6(const packet_t *packet) {
    size_t ip_offset = ETHERNET_HEADER_SIZE;

    if (packet->captured_packet_length < ip_offset + IPV6_HEADER_SIZE) {
        printf("Packet validation failed: packet too small for IPv6 header\n");
        return 1;
    }

    uint8_t version = packet->packet_data[ip_offset] >> IPV6_VERSION_SHIFT;

    if (version != 6) {
        printf("Packet validation failed: invalid IPv6 version: %u\n", version);
        return 1;
    }

    uint16_t payload_length =
        ((uint16_t)packet->packet_data[ip_offset + IPV6_PAYLOAD_LENGTH_OFFSET] << 8) |
        packet->packet_data[ip_offset + IPV6_PAYLOAD_LENGTH_OFFSET + 1];

    if (payload_length > packet->captured_packet_length - ip_offset - IPV6_HEADER_SIZE) {
        printf("Packet validation failed: IPv6 payload exceeds packet length\n");
        return 1;
    }

    return 0;
}

static int validate_packet(const packet_t *packet) {
    if (!packet) {
        printf("Packet validation failed: packet is NULL\n");
        return 1;
    }

    if (!packet->packet_data) {
        printf("Packet validation failed: packet data is NULL\n");
        return 1;
    }

    if (packet->captured_packet_length < ETHERNET_HEADER_SIZE) {
        printf("Packet validation failed: packet too small for Ethernet header\n");
        return 1;
    }

    uint16_t ether_type =
        ((uint16_t)packet->packet_data[ETHERNET_ETHERTYPE_OFFSET] << 8) |
        packet->packet_data[ETHERNET_ETHERTYPE_OFFSET + 1];

    if (ether_type == ETHERNET_ETHERTYPE_IPV4)
        return validate_ipv4(packet);

    if (ether_type == ETHERNET_ETHERTYPE_IPV6)
        return validate_ipv6(packet);

    printf("Packet validation: unsupported EtherType: 0x%04X\n", ether_type);

    return 0;
}

int validate_packets(const pcapng_t *pcapng) {
    for (size_t i = 0; i < pcapng->packet_count; i++) {
        const packet_t *pkt = &pcapng->packets[i];

        if (validate_packet(pkt) != 0) {
            return 1;
        }
    }

    printf("PACKET Validation: OK\n");
    return 0;
}

