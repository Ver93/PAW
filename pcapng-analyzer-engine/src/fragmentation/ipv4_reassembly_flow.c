#include <stdlib.h>
#include <string.h>

#include "ipv4_reassembly_flow.h"

void init_ipv4_reassembly(
    ipv4_reassembly_t *reassembly
) {
    if (!reassembly)
        return;

    memset(
        reassembly,
        0,
        sizeof(*reassembly)
    );
}

void handle_ipv4_fragment_for_flows(
    const packet_t *packet,
    const ipv4_t *ipv4,
    ipv4_reassembly_t *reassembly,
    flow_table_t *flows,
    size_t packet_index
) {
    if (
        !packet ||
        !ipv4 ||
        !reassembly ||
        !flows
    ) {
        return;
    }

    ipv4_fragment_t *fragment =
        make_ipv4_fragment(
            packet,
            ipv4
        );

    if (!fragment)
        return;

    if (
        !add_fragment_to_reassembly(
            reassembly,
            fragment
        )
    ) {
        free(fragment);
        return;
    }

    for (
        size_t i = 0;
        i < reassembly->group_count;
        i++
    ) {

        ipv4_fragment_group_t *group =
            reassembly->groups[i];

        if (!group)
            continue;

        if (
            validate_fragment_group(group) !=
            IPV4_REASSEMBLY_COMPLETE
        ) {
            continue;
        }

        if (
            group->protocol !=
            IP_PROTOCOL_UDP
        ) {
            continue;
        }

        ipv4_reassembled_payload_t *payload =
            reassemble_ipv4_group(group);

        if (!payload)
            continue;

        ipv4_reassembled_udp_t *udp =
            parse_reassembled_udp(
                payload,
                group
            );

        if (!udp) {
            free(payload->data);
            free(payload);
            continue;
        }

        flow_endpoint_t source = {
            .port = udp->source_port
        };

        flow_endpoint_t destination = {
            .port = udp->destination_port
        };

        memcpy(
            source.ip,
            udp->source_ip,
            sizeof(source.ip)
        );

        memcpy(
            destination.ip,
            udp->destination_ip,
            sizeof(destination.ip)
        );

        add_flow_packet_payload(
            flows,
            source,
            destination,
            FLOW_PROTOCOL_UDP,
            packet_index,
            udp->data,
            udp->data_length,
            0,
            1
        );

        free(udp);

        free(payload->data);
        free(payload);
        
        for (
            size_t j = i;
            j + 1 < reassembly->group_count;
            j++
        ) {
            reassembly->groups[j] =
                reassembly->groups[j + 1];
        }

        reassembly->group_count--;

        free(group->fragments);
        free(group);

        i--;
    }
}