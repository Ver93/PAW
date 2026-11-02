#ifndef IPV4_REASSEMBLY_UDP_H
#define IPV4_REASSEMBLY_UDP_H

#include <stddef.h>
#include <stdint.h>

#include "ipv4_reassembly.h"

typedef struct {
    uint8_t source_ip[4];
    uint8_t destination_ip[4];

    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;

    const uint8_t *data;
    size_t data_length;
} ipv4_reassembled_udp_t;

ipv4_reassembled_udp_t *parse_reassembled_udp(
    const ipv4_reassembled_payload_t *payload,
    const ipv4_fragment_group_t *group);

int validate_udp_checksum(
    const ipv4_reassembled_udp_t *udp);

#endif