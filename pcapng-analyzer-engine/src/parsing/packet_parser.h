#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "pcapng.h"
#include "pcapng_blocks.h"
#include "constants.h"
#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"

#include "packet_validation.h"
#include "ethernet_parser.h"
#include "ipv6_parser.h"
#include "ipv4_parser.h"

int parse_packets(const pcapng_t *pcang);

#endif