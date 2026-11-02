#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    uint32_t rest_of_header;

    size_t payload_offset;
    size_t payload_length;
} icmp_t;

#endif