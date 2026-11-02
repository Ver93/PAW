#ifndef PROTOCOL_PARSER_H
#define PROTOCOL_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "pcapng_blocks.h"
#include "constants.h"
#include "endianness.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"

void *parse_protocol(const packet_t *packet, uint8_t protocol, size_t offset, size_t payload_length);

#endif