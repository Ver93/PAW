#ifndef IPV4_PARSER_H
#define IPV4_PARSER_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "pcapng_blocks.h"
#include "ipv4.h"
#include "constants.h"

ipv4_t parse_ipv4(const packet_t *packet);

#endif