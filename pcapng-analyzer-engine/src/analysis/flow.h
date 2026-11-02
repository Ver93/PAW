#ifndef FLOW_H
#define FLOW_H

#include <stddef.h>
#include <stdint.h>
#include "protocol_node.h"

#include "packet_parser.h"

typedef enum {
    FLOW_PROTOCOL_UNKNOWN = 0,
    FLOW_PROTOCOL_TCP,
    FLOW_PROTOCOL_UDP,
    FLOW_PROTOCOL_ICMP
} flow_protocol_t;

typedef struct {
    uint8_t ip[4];
    uint16_t port;
} flow_endpoint_t;

typedef struct {
    size_t packet_index;
    int direction;
    uint32_t sequence;

    uint8_t *payload;
    size_t payload_length;

    int reassembled;
} flow_packet_t;

typedef struct {
    flow_endpoint_t a;
    flow_endpoint_t b;
    flow_protocol_t protocol;

    size_t packets;
    size_t packets_a_to_b;
    size_t packets_b_to_a;

    flow_packet_t *packet_data;
    size_t packet_count;
    size_t packet_capacity;
} network_flow_t;

typedef struct {
    network_flow_t *flows;
    size_t count;
    size_t capacity;
} flow_table_t;

void init_flow_table(
    flow_table_t *table
);

void analyze_flow(
    const packet_t *packet,
    const protocol_chain_t *chain,
    flow_table_t *table,
    size_t packet_index
);

void free_flow_table(
    flow_table_t *table
);

const char *flow_protocol_name(
    flow_protocol_t protocol
);

int add_flow_packet(
    flow_table_t *table,
    flow_endpoint_t source,
    flow_endpoint_t destination,
    flow_protocol_t protocol,
    const packet_t *packet,
    size_t packet_index,
    size_t payload_offset,
    size_t payload_length,
    uint32_t sequence
);

int add_flow_packet_payload(
    flow_table_t *table,
    flow_endpoint_t source,
    flow_endpoint_t destination,
    flow_protocol_t protocol,
    size_t packet_index,
    const uint8_t *payload,
    size_t payload_length,
    uint32_t sequence,
    int reassembled
);

network_flow_t *find_flow(
    flow_table_t *table,
    const flow_endpoint_t *a,
    const flow_endpoint_t *b,
    flow_protocol_t protocol
);

#endif