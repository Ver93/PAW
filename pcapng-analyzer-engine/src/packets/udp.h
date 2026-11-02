#ifndef UDP_H
#define UDP_H

#include <stdint.h>

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;

    size_t payload_offset;
    size_t payload_length;
} udp_t;

#endif