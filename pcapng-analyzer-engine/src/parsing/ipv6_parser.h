#ifndef IPV6_PARSER_H
#define IPV6_PARSER_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "pcapng_blocks.h"
#include "constants.h"
#include "ipv6.h"

ipv6_t parse_ipv6(const packet_t *packet);

#endif