#ifndef IPV4_FRAGMENTATION_H
#define IPV4_FRAGMENTATION_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pcapng_blocks.h"
#include "ipv4.h"

typedef struct {
    uint8_t source_ip[4];
    uint8_t destination_ip[4];

    uint16_t identification;
    uint8_t protocol;

    size_t offset;
    size_t length;

    int more_fragments;

    const uint8_t *data;
} ipv4_fragment_t;

ipv4_fragment_t *make_ipv4_fragment(const packet_t *packet, const ipv4_t *ipv4);

#endif