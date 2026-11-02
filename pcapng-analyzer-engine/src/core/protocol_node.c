#include <stdio.h>
#include <stdlib.h>

#include "protocol_node.h"

static protocol_node_t *new_node(protocol_type_t type, void *data) {
    protocol_node_t *node = malloc(sizeof(protocol_node_t));
    if (!node) return NULL;

    node->type = type;
    node->data = data;
    node->next = NULL;

    return node;
}

static void chain_init(protocol_chain_t *chain) {
    chain->root = NULL;
    chain->last = NULL;
}

static void chain_append(protocol_chain_t *chain, protocol_node_t *node) {
    if (!chain->root) {
        chain->root = node;
        chain->last = node;
        return;
    }

    chain->last->next = node;
    chain->last = node;
}

static void chain_free(protocol_chain_t *chain) {
    if (!chain)
        return;

    protocol_node_t *node = chain->root;

    while (node) {
        protocol_node_t *next = node->next;

        free(node->data);
        free(node);

        node = next;
    }

    chain->root = NULL;
    chain->last = NULL;
}

/* BUILD CHAIN FOR ONE PACKET */

static protocol_chain_t *build_chain(const packet_t *packet) {
    if (!packet || !packet->packet_data ||
        packet->captured_packet_length < ETHERNET_HEADER_SIZE)
        return NULL;

    protocol_chain_t *chain = malloc(sizeof(protocol_chain_t));
    if (!chain)
        return NULL;

    chain_init(chain);

    /* ETHERNET */
    ethernet_t *eth = malloc(sizeof(ethernet_t));
    if (!eth) {
        free(chain);
        return NULL;
    }

    *eth = parse_ethernet(packet);
    chain_append(chain, new_node(PROTO_ETHERNET, eth));

    /* NEXT PROTOCOL */
    switch (eth->ether_type) {

    case ETHERNET_ETHERTYPE_IPV4: {
        ipv4_t *ipv4 = malloc(sizeof(ipv4_t));
        if (!ipv4)
            return chain;

        *ipv4 = parse_ipv4(packet);
        chain_append(chain, new_node(PROTO_IPV4, ipv4));

        void *proto =
            parse_protocol(packet,
                           ipv4->ip_protocol,
                           ipv4->payload_offset,
                           ipv4->ip_payload_length);

        if (proto) {
            protocol_type_t type = PROTO_UNKNOWN;

            switch (ipv4->ip_protocol) {
                case IP_PROTOCOL_ICMP: type = PROTO_ICMP; break;
                case IP_PROTOCOL_TCP:  type = PROTO_TCP;  break;
                case IP_PROTOCOL_UDP:  type = PROTO_UDP;  break;
            }

            chain_append(chain, new_node(type, proto));
        }

        return chain;
    }

    case ETHERNET_ETHERTYPE_IPV6: {
        ipv6_t *ipv6 = malloc(sizeof(ipv6_t));
        if (!ipv6)
            return chain;

        *ipv6 = parse_ipv6(packet);
        chain_append(chain, new_node(PROTO_IPV6, ipv6));

        void *proto =
            parse_protocol(packet,
                           ipv6->next_header,
                           ipv6->payload_offset,
                           ipv6->payload_length);

        if (proto) {
            protocol_type_t type = PROTO_UNKNOWN;

            switch (ipv6->next_header) {
                case IP_PROTOCOL_ICMP: type = PROTO_ICMP; break;
                case IP_PROTOCOL_TCP:  type = PROTO_TCP;  break;
                case IP_PROTOCOL_UDP:  type = PROTO_UDP;  break;
            }

            chain_append(chain, new_node(type, proto));
        }

        return chain;
    }

    default:
        return chain;
    }
}

void free_all_chains(protocol_chain_t **chains) {
    if (!chains)
        return;

    for (size_t i = 0; chains[i] != NULL; i++) {
        protocol_chain_t *chain = chains[i];

        protocol_node_t *node = chain->root;
        while (node) {
            protocol_node_t *next = node->next;

            free(node->data);
            free(node);

            node = next;
        }

        free(chain);
    }

    free(chains);
}


protocol_chain_t **build_all_chains(const pcapng_t *pcapng) {
    if (!pcapng || pcapng->packet_count == 0)
        return NULL;

    protocol_chain_t **chains =
        malloc(sizeof(protocol_chain_t*) * (pcapng->packet_count + 1));

    if (!chains)
        return NULL;

    for (size_t i = 0; i < pcapng->packet_count; i++) {
        chains[i] = build_chain(&pcapng->packets[i]);
    }

    chains[pcapng->packet_count] = NULL;

    printf("NODES: %zu nodes created!\n", pcapng->packet_count);

    return chains;
}