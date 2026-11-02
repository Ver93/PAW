#ifndef PACKET_VALIDATION_H
#define PACKET_VALIDATION_H

#include "pcapng_blocks.h"
#include "pcapng.h"

// int validate_packet(const packet_t *packet);
// int validate_ipv4(const packet_t *packet);
// int validate_ipv6(const packet_t *packet);

int validate_packets(const pcapng_t *pcapng);

#endif