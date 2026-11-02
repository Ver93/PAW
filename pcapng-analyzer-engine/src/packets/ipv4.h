#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t ip_version;
    uint8_t ihl;
    uint8_t tos;
    uint16_t total_length;

    uint16_t ip_identification;

    int reserved_flag;
    int dont_fragment;
    int more_fragments;

    uint16_t fragment_offset;

    uint8_t ttl;
    uint8_t ip_protocol;
    uint16_t header_checksum;

    uint8_t source_ip[4];
    uint8_t destination_ip[4];

    uint16_t source_port;
    uint16_t destination_port;

    int is_fragment;

    size_t ip_payload_offset;
    size_t ip_payload_length;

    size_t payload_offset;
    size_t payload_length;
} ipv4_t;

#endif