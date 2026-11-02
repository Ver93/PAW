#include "ipv4_fragment.h"

ipv4_fragment_t *make_ipv4_fragment(const packet_t *packet, const ipv4_t *ipv4)
{
    if (!packet || !ipv4)
        return NULL;

    ipv4_fragment_t *fragment = malloc(sizeof(ipv4_fragment_t));

    if (!fragment)
        return NULL;

    memcpy(fragment->source_ip, ipv4->source_ip, sizeof(fragment->source_ip));
    memcpy(fragment->destination_ip, ipv4->destination_ip, sizeof(fragment->destination_ip));

    fragment->identification = ipv4->ip_identification;
    fragment->protocol = ipv4->ip_protocol;
    fragment->offset = ipv4->fragment_offset * 8;
    fragment->length = ipv4->ip_payload_length;
    fragment->more_fragments = ipv4->more_fragments;
    fragment->data = packet->packet_data + ipv4->ip_payload_offset;

    return fragment;
}