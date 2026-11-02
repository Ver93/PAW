#ifndef JSON_EXPORT_H
#define JSON_EXPORT_H

#include "protocol_node.h"

#include "ipv4.h"
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"

#include "ethernet.h"

void print_protocol_nodes_json(const protocol_chain_t *chain, size_t packet_index);

#endif