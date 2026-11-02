#include <stdlib.h>
#include <string.h>

#include "flow.h"

static int compare_endpoint(
    const flow_endpoint_t *a,
    const flow_endpoint_t *b
) {
    int ip_compare =
        memcmp(
            a->ip,
            b->ip,
            sizeof(a->ip)
        );

    if (ip_compare != 0)
        return ip_compare;

    if (a->port < b->port)
        return -1;

    if (a->port > b->port)
        return 1;

    return 0;
}

static int endpoint_equal(
    const flow_endpoint_t *a,
    const flow_endpoint_t *b
) {
    return compare_endpoint(a, b) == 0;
}

static void normalize_endpoints(
    flow_endpoint_t *a,
    flow_endpoint_t *b
) {
    if (compare_endpoint(a, b) > 0) {
        flow_endpoint_t temp = *a;
        *a = *b;
        *b = temp;
    }
}

static int ensure_capacity(
    flow_table_t *table
) {
    if (table->count < table->capacity)
        return 0;

    size_t new_capacity;

    if (table->capacity == 0)
        new_capacity = 32;
    else
        new_capacity = table->capacity * 2;

    network_flow_t *new_flows =
        realloc(
            table->flows,
            new_capacity * sizeof(network_flow_t)
        );

    if (!new_flows)
        return -1;

    table->flows = new_flows;
    table->capacity = new_capacity;

    return 0;
}

static int ensure_packet_capacity(
    network_flow_t *flow
) {
    if (flow->packet_count < flow->packet_capacity)
        return 0;

    size_t new_capacity;

    if (flow->packet_capacity == 0)
        new_capacity = 32;
    else
        new_capacity = flow->packet_capacity * 2;

    flow_packet_t *new_packets =
        realloc(
            flow->packet_data,
            new_capacity * sizeof(flow_packet_t)
        );

    if (!new_packets)
        return -1;

    flow->packet_data = new_packets;
    flow->packet_capacity = new_capacity;

    return 0;
}

network_flow_t *find_flow(
    flow_table_t *table,
    const flow_endpoint_t *a,
    const flow_endpoint_t *b,
    flow_protocol_t protocol
) {
    if (!table || !a || !b)
        return NULL;

    for (size_t i = 0; i < table->count; i++) {

        network_flow_t *flow =
            &table->flows[i];

        if (flow->protocol != protocol)
            continue;

        if (
            endpoint_equal(&flow->a, a) &&
            endpoint_equal(&flow->b, b)
        ) {
            return flow;
        }
    }

    return NULL;
}

static network_flow_t *create_flow(
    flow_table_t *table,
    flow_endpoint_t a,
    flow_endpoint_t b,
    flow_protocol_t protocol
) {
    if (ensure_capacity(table) != 0)
        return NULL;

    normalize_endpoints(
        &a,
        &b
    );

    network_flow_t *flow =
        &table->flows[table->count];

    memset(
        flow,
        0,
        sizeof(*flow)
    );

    flow->a = a;
    flow->b = b;
    flow->protocol = protocol;

    table->count++;

    return flow;
}

void init_flow_table(
    flow_table_t *table
) {
    if (!table)
        return;

    memset(
        table,
        0,
        sizeof(*table)
    );
}

void free_flow_table(
    flow_table_t *table
) {
    if (!table)
        return;

    for (size_t i = 0; i < table->count; i++) {

        network_flow_t *flow =
            &table->flows[i];

        for (size_t j = 0;
             j < flow->packet_count;
             j++) {

            free(
                flow->packet_data[j].payload
            );

            flow->packet_data[j].payload = NULL;
            flow->packet_data[j].payload_length = 0;
        }

        free(flow->packet_data);

        flow->packet_data = NULL;
        flow->packet_count = 0;
        flow->packet_capacity = 0;
    }

    free(table->flows);

    table->flows = NULL;
    table->count = 0;
    table->capacity = 0;
}

static int get_ipv4(
    const protocol_chain_t *chain,
    ipv4_t **result
) {
    if (!chain || !result)
        return 0;

    const protocol_node_t *node =
        chain->root;

    while (node) {

        if (node->type == PROTO_IPV4) {
            *result = node->data;
            return 1;
        }

        node = node->next;
    }

    return 0;
}

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
) {
    if (!table)
        return -1;

    flow_endpoint_t normalized_a = source;
    flow_endpoint_t normalized_b = destination;

    normalize_endpoints(
        &normalized_a,
        &normalized_b
    );

    network_flow_t *flow =
        find_flow(
            table,
            &normalized_a,
            &normalized_b,
            protocol
        );

    if (!flow) {

        flow =
            create_flow(
                table,
                normalized_a,
                normalized_b,
                protocol
            );

        if (!flow)
            return -1;
    }

    int direction;

    if (
        endpoint_equal(&source, &flow->a) &&
        endpoint_equal(&destination, &flow->b)
    ) {
        flow->packets_a_to_b++;
        direction = 0;
    } else {
        flow->packets_b_to_a++;
        direction = 1;
    }

    if (ensure_packet_capacity(flow) != 0)
        return -1;

    flow_packet_t *flow_packet =
        &flow->packet_data[flow->packet_count];

    memset(
        flow_packet,
        0,
        sizeof(*flow_packet)
    );

    flow_packet->packet_index = packet_index;
    flow_packet->direction = direction;
    flow_packet->sequence = sequence;
    flow_packet->reassembled = reassembled;

    if (payload && payload_length > 0) {

        flow_packet->payload =
            malloc(payload_length);

        if (!flow_packet->payload)
            return -1;

        memcpy(
            flow_packet->payload,
            payload,
            payload_length
        );

        flow_packet->payload_length =
            payload_length;
    }

    flow->packet_count++;
    flow->packets++;

    return 0;
}

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
) {
    const uint8_t *payload = NULL;

    if (
        packet &&
        packet->packet_data &&
        payload_length > 0 &&
        payload_offset <= packet->captured_packet_length &&
        payload_length <=
            packet->captured_packet_length - payload_offset
    ) {
        payload =
            packet->packet_data + payload_offset;
    } else {
        payload_length = 0;
    }

    return add_flow_packet_payload(
        table,
        source,
        destination,
        protocol,
        packet_index,
        payload,
        payload_length,
        sequence,
        0
    );
}

void analyze_flow(
    const packet_t *packet,
    const protocol_chain_t *chain,
    flow_table_t *table,
    size_t packet_index
) {
    if (!packet || !chain || !table)
        return;

    ipv4_t *ipv4 = NULL;

    if (!get_ipv4(chain, &ipv4))
        return;

    const protocol_node_t *node =
        chain->root;

    while (node) {

        if (node->type == PROTO_TCP) {

            tcp_t *tcp = node->data;

            flow_endpoint_t source = {
                .port = tcp->source_port
            };

            flow_endpoint_t destination = {
                .port = tcp->destination_port
            };

            memcpy(
                source.ip,
                ipv4->source_ip,
                sizeof(source.ip)
            );

            memcpy(
                destination.ip,
                ipv4->destination_ip,
                sizeof(destination.ip)
            );

            add_flow_packet(
                table,
                source,
                destination,
                FLOW_PROTOCOL_TCP,
                packet,
                packet_index,
                tcp->payload_offset,
                tcp->payload_length,
                tcp->sequence_number
            );

            return;
        }

        if (node->type == PROTO_UDP) {

            udp_t *udp = node->data;

            flow_endpoint_t source = {
                .port = udp->source_port
            };

            flow_endpoint_t destination = {
                .port = udp->destination_port
            };

            memcpy(
                source.ip,
                ipv4->source_ip,
                sizeof(source.ip)
            );

            memcpy(
                destination.ip,
                ipv4->destination_ip,
                sizeof(destination.ip)
            );

            add_flow_packet(
                table,
                source,
                destination,
                FLOW_PROTOCOL_UDP,
                packet,
                packet_index,
                udp->payload_offset,
                udp->payload_length,
                0
            );

            return;
        }

        if (node->type == PROTO_ICMP) {

            icmp_t *icmp = node->data;

            flow_endpoint_t source = {
                .port = 0
            };

            flow_endpoint_t destination = {
                .port = 0
            };

            memcpy(
                source.ip,
                ipv4->source_ip,
                sizeof(source.ip)
            );

            memcpy(
                destination.ip,
                ipv4->destination_ip,
                sizeof(destination.ip)
            );

            add_flow_packet(
                table,
                source,
                destination,
                FLOW_PROTOCOL_ICMP,
                packet,
                packet_index,
                icmp->payload_offset,
                icmp->payload_length,
                0
            );

            return;
        }

        node = node->next;
    }
}

const char *flow_protocol_name(
    flow_protocol_t protocol
) {
    switch (protocol) {

    case FLOW_PROTOCOL_TCP:
        return "TCP";

    case FLOW_PROTOCOL_UDP:
        return "UDP";

    case FLOW_PROTOCOL_ICMP:
        return "ICMP";

    default:
        return "UNKNOWN";
    }
}