#ifndef PROTOCOL_VALIDATION_H
#define PROTOCOL_VALIDATION_H

#include <stdint.h>
#include <stddef.h>

#include "pcapng_blocks.h"

int validate_icmp(const packet_t *packet, size_t offset, size_t payload_length, int more_fragments);
int validate_tcp(const packet_t *packet, size_t offset, size_t payload_length, int more_fragments);
int validate_udp(const packet_t *packet, size_t offset, size_t payload_length);
int validate_protocol(const packet_t *packet, uint8_t protocol, size_t offset, size_t payload_length, int more_fragments);

#endif