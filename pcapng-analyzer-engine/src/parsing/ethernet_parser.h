#ifndef ETHERNET_PARSER_H
#define ETHERNET_PARSER_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "pcapng_blocks.h"
#include "ethernet.h"

ethernet_t parse_ethernet(const packet_t *packet);

#endif