#include "packet_parser.h"
#include <stdlib.h>

static int parse_packet(const packet_t *packet) {
    if (!packet || !packet->packet_data || packet->captured_packet_length < ETHERNET_HEADER_SIZE)
        return 1;

    ethernet_t eth = parse_ethernet(packet);

    switch (eth.ether_type) {
    case ETHERNET_ETHERTYPE_IPV4:
        ipv4_t ipv4 = parse_ipv4(packet);
        return 0;

    case ETHERNET_ETHERTYPE_IPV6:
        ipv6_t ipv6 = parse_ipv6(packet);
        return 0;

    default:
        return 1;
    }
}

int parse_packets(const pcapng_t *pcapng) {
    for (size_t i = 0; i < pcapng->packet_count; i++) {
        packet_t *pkt = &pcapng->packets[i];
        parse_packet(pkt);
    }
    return 0;
}
