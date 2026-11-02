#ifndef PROTOCOL_NODE_H
#define PROTOCOL_NODE_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"

#include "tcp.h"
#include "udp.h"
#include "icmp.h"

#include "ethernet_parser.h"
#include "ipv4_parser.h"
#include "ipv6_parser.h"
#include "protocol_parser.h"
#include "pcapng.h"
#include "pcapng_blocks.h"
#include "constants.h"

typedef enum {
    PROTO_UNKNOWN,

    PROTO_ETHERNET,
    PROTO_IPV4,
    PROTO_IPV6,

    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,

    PROTO_HTTP,
    PROTO_HTTPS,
    PROTO_DNS,
    PROTO_FTP,
    PROTO_SSH,
    PROTO_SMTP,
    PROTO_IMAP,
    PROTO_DHCP
} protocol_type_t;

typedef struct protocol_node {
    protocol_type_t type;
    void *data;
    struct protocol_node *next;
} protocol_node_t;

typedef struct {
    protocol_node_t *root;
    protocol_node_t *last;
} protocol_chain_t;

protocol_chain_t **build_all_chains(const pcapng_t *pcapng);
void free_all_chains(protocol_chain_t **chains);

#endif
