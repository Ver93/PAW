#ifndef IPV4_REASSEMBLY_H
#define IPV4_REASSEMBLY_H

#include <stddef.h>
#include <stdint.h>

#include "ipv4_fragment.h"

typedef enum {
    IPV4_REASSEMBLY_INCOMPLETE,
    IPV4_REASSEMBLY_COMPLETE,
    IPV4_REASSEMBLY_OVERLAP,
    IPV4_REASSEMBLY_CONFLICT
} ipv4_reassembly_status_t;

typedef struct {
    uint16_t identification;

    uint8_t source_ip[4];
    uint8_t destination_ip[4];

    uint8_t protocol;

    ipv4_fragment_t **fragments;
    size_t fragment_count;
} ipv4_fragment_group_t;

typedef struct {
    ipv4_fragment_group_t **groups;
    size_t group_count;
} ipv4_reassembly_t;

typedef struct {
    uint8_t *data;
    size_t length;
} ipv4_reassembled_payload_t;

int fragment_belongs_to_group(
    const ipv4_fragment_group_t *group,
    const ipv4_fragment_t *fragment);

int add_fragment(
    ipv4_fragment_group_t *group,
    ipv4_fragment_t *fragment);

int add_fragment_to_reassembly(
    ipv4_reassembly_t *reassembly,
    ipv4_fragment_t *fragment);

ipv4_reassembled_payload_t *reassemble_ipv4_group(
    const ipv4_fragment_group_t *group);

void free_ipv4_reassembly(
    ipv4_reassembly_t *reassembly);

ipv4_reassembly_status_t validate_fragment_group(
    const ipv4_fragment_group_t *group);

ipv4_reassembled_payload_t *get_reassembled_payload(
    const ipv4_reassembly_t *reassembly,
    const ipv4_t *ipv4
);

#endif
