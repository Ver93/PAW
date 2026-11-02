#ifndef IPV4_REASSEMBLY_FLOW_H
#define IPV4_REASSEMBLY_FLOW_H

#include <stddef.h>

#include "ipv4_reassembly.h"
#include "ipv4_fragment.h"
#include "ipv4_reassembly_udp.h"
#include "flow.h"
#include "packet_parser.h"

void init_ipv4_reassembly(ipv4_reassembly_t *reassembly);

void handle_ipv4_fragment_for_flows(
    const packet_t *packet,
    const ipv4_t *ipv4,
    ipv4_reassembly_t *reassembly,
    flow_table_t *flows,
    size_t packet_index
);

#endif
