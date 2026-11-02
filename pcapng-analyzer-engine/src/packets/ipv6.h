#ifndef IPV6_H
#define IPV6_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t ip_version;
    uint8_t traffic_class;
    uint32_t flow_label;

    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;

    uint8_t source_ip[16];
    uint8_t destination_ip[16];

    uint16_t source_port;
    uint16_t destination_port;

    size_t payload_offset;
} ipv6_t;

#endif