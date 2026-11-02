#include "ipv4_reassembly.h"

#include <stdlib.h>
#include <string.h>

   // if (ipv4->is_fragment) {

        //     ipv4_fragment_t *frag = make_ipv4_fragment(packet, ipv4);

        //     if (frag) {
        //         if (!add_fragment_to_reassembly(reassembly, frag))
        //             free(frag);
        //     }

        //     // If NOT first fragment → stop here
        //     if (ipv4->fragment_offset != 0)
        //         return chain;

        //     // If last fragment → try reassembly
        //     if (!ipv4->more_fragments) {

        //         packet_t *reassembled =
        //             get_reassembled_packet(reassembly, ipv4);

        //         if (reassembled) {

        //             protocol_node_t *proto =
        //                 parse_protocol(
        //                     reassembled,
        //                     ipv4->ip_protocol,
        //                     ipv4->payload_offset,
        //                     ipv4->ip_payload_length
        //                 );

        //             if (proto) {
        //                 chain_append(chain, proto);
        //                 detect_and_append_application_protocol(
        //                     chain, proto, reassembled
        //                 );
        //             }

        //             return chain;
        //         }
        //     }
        // }

int fragment_belongs_to_group(
    const ipv4_fragment_group_t *group,
    const ipv4_fragment_t *fragment
) {
    if (!group || !fragment)
        return 0;

    if (group->identification != fragment->identification)
        return 0;

    if (group->protocol != fragment->protocol)
        return 0;

    if (
        memcmp(
            group->source_ip,
            fragment->source_ip,
            sizeof(group->source_ip)
        ) != 0
    )
        return 0;

    if (
        memcmp(
            group->destination_ip,
            fragment->destination_ip,
            sizeof(group->destination_ip)
        ) != 0
    )
        return 0;

    return 1;
}

int add_fragment(
    ipv4_fragment_group_t *group,
    ipv4_fragment_t *fragment
) {
    if (!group || !fragment)
        return 0;

    ipv4_fragment_t **fragments =
        realloc(
            group->fragments,
            (group->fragment_count + 1) *
            sizeof(ipv4_fragment_t *)
        );

    if (!fragments)
        return 0;

    group->fragments = fragments;

    group->fragments[
        group->fragment_count
    ] = fragment;

    group->fragment_count++;

    return 1;
}

int add_fragment_to_reassembly(
    ipv4_reassembly_t *reassembly,
    ipv4_fragment_t *fragment
) {
    if (!reassembly || !fragment)
        return 0;

    for (
        size_t i = 0;
        i < reassembly->group_count;
        i++
    ) {

        ipv4_fragment_group_t *group =
            reassembly->groups[i];

        if (
            fragment_belongs_to_group(
                group,
                fragment
            )
        ) {
            return add_fragment(
                group,
                fragment
            );
        }
    }

    ipv4_fragment_group_t *group =
        calloc(
            1,
            sizeof(ipv4_fragment_group_t)
        );

    if (!group)
        return 0;

    memcpy(
        group->source_ip,
        fragment->source_ip,
        sizeof(group->source_ip)
    );

    memcpy(
        group->destination_ip,
        fragment->destination_ip,
        sizeof(group->destination_ip)
    );

    group->identification =
        fragment->identification;

    group->protocol =
        fragment->protocol;

    ipv4_fragment_group_t **groups =
        realloc(
            reassembly->groups,
            (reassembly->group_count + 1) *
            sizeof(ipv4_fragment_group_t *)
        );

    if (!groups) {
        free(group);
        return 0;
    }

    reassembly->groups = groups;

    reassembly->groups[
        reassembly->group_count
    ] = group;

    reassembly->group_count++;

    return add_fragment(
        group,
        fragment
    );
}

ipv4_reassembled_payload_t *reassemble_ipv4_group(
    const ipv4_fragment_group_t *group
) {
    if (
        !group ||
        group->fragment_count == 0
    ) {
        return NULL;
    }

    if (
        validate_fragment_group(group) !=
        IPV4_REASSEMBLY_COMPLETE
    ) {
        return NULL;
    }

    size_t total_length = 0;

    for (
        size_t i = 0;
        i < group->fragment_count;
        i++
    ) {

        const ipv4_fragment_t *fragment =
            group->fragments[i];

        if (!fragment)
            continue;

        size_t end =
            fragment->offset +
            fragment->length;

        if (end > total_length)
            total_length = end;
    }

    if (total_length == 0)
        return NULL;

    ipv4_reassembled_payload_t *payload =
        malloc(
            sizeof(ipv4_reassembled_payload_t)
        );

    if (!payload)
        return NULL;

    payload->data =
        calloc(
            1,
            total_length
        );

    if (!payload->data) {
        free(payload);
        return NULL;
    }

    payload->length = total_length;

    for (
        size_t i = 0;
        i < group->fragment_count;
        i++
    ) {

        ipv4_fragment_t *fragment =
            group->fragments[i];

        if (!fragment)
            continue;

        memcpy(
            payload->data + fragment->offset,
            fragment->data,
            fragment->length
        );
    }

    return payload;
}

ipv4_reassembled_payload_t *get_reassembled_payload(
    const ipv4_reassembly_t *reassembly,
    const ipv4_t *ipv4
) {
    if (!reassembly || !ipv4)
        return NULL;

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
            group->identification !=
            ipv4->ip_identification
        )
            continue;

        if (
            group->protocol !=
            ipv4->ip_protocol
        )
            continue;

        if (
            memcmp(
                group->source_ip,
                ipv4->source_ip,
                sizeof(group->source_ip)
            ) != 0
        )
            continue;

        if (
            memcmp(
                group->destination_ip,
                ipv4->destination_ip,
                sizeof(group->destination_ip)
            ) != 0
        )
            continue;

        return reassemble_ipv4_group(group);
    }

    return NULL;
}

void free_ipv4_reassembly(
    ipv4_reassembly_t *reassembly
) {
    if (!reassembly)
        return;

    for (
        size_t i = 0;
        i < reassembly->group_count;
        i++
    ) {

        ipv4_fragment_group_t *group =
            reassembly->groups[i];

        if (!group)
            continue;

        for (
            size_t j = 0;
            j < group->fragment_count;
            j++
        ) {
            free(group->fragments[j]);
        }

        free(group->fragments);
        free(group);
    }

    free(reassembly->groups);

    reassembly->groups = NULL;
    reassembly->group_count = 0;
}