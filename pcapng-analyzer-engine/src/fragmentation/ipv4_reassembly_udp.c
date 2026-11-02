#include "ipv4_reassembly_udp.h"

ipv4_reassembled_udp_t *parse_reassembled_udp(const ipv4_reassembled_payload_t *payload, const ipv4_fragment_group_t *group) {
    if (!payload || !payload->data || !group)
        return NULL;

    if (payload->length < 8)
        return NULL;

    ipv4_reassembled_udp_t *udp =
        malloc(sizeof(ipv4_reassembled_udp_t));

    if (!udp)
        return NULL;

    memcpy(udp->source_ip,
           group->source_ip,
           sizeof(udp->source_ip));

    memcpy(udp->destination_ip,
           group->destination_ip,
           sizeof(udp->destination_ip));

    udp->source_port =
        ((uint16_t)payload->data[0] << 8) |
        payload->data[1];

    udp->destination_port =
        ((uint16_t)payload->data[2] << 8) |
        payload->data[3];

    udp->length =
        ((uint16_t)payload->data[4] << 8) |
        payload->data[5];

    udp->checksum =
        ((uint16_t)payload->data[6] << 8) |
        payload->data[7];

    if (udp->length < 8 ||
        udp->length > payload->length) {
        free(udp);
        return NULL;
    }

    udp->data = payload->data + 8;
    udp->data_length = udp->length - 8;

    return udp;
}

int validate_udp_checksum(
    const ipv4_reassembled_udp_t *udp)
{
    if (!udp || !udp->data)
        return 0;

    uint32_t sum = 0;

    for (int i = 0; i < 4; i += 2) {
        sum += ((uint16_t)udp->source_ip[i] << 8) | udp->source_ip[i + 1];

        sum += ((uint16_t)udp->destination_ip[i] << 8) | udp->destination_ip[i + 1];
    }

    sum += 17;
    sum += udp->length;

    sum += udp->source_port;
    sum += udp->destination_port;
    sum += udp->length;

    for (size_t i = 0; i + 1 < udp->data_length; i += 2) {
        sum +=
            ((uint16_t)udp->data[i] << 8) |
            udp->data[i + 1];

        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }

    if (udp->data_length % 2 != 0) {
        sum +=
            (uint16_t)udp->data[udp->data_length - 1] << 8;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    uint16_t checksum =
        (uint16_t)~sum;

    return checksum == udp->checksum;
}