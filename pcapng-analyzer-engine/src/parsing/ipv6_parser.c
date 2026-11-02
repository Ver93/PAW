#include "ipv6_parser.h"

ipv6_t parse_ipv6(const packet_t *packet) {
    ipv6_t ipv6 = {0};
    size_t offset = ETHERNET_HEADER_SIZE;
    uint32_t first_word = ((uint32_t)packet->packet_data[offset] << 24) | ((uint32_t)packet->packet_data[offset + 1] << 16) | ((uint32_t)packet->packet_data[offset + 2] << 8) | packet->packet_data[offset + 3];
    ipv6.ip_version = (first_word >> 28) & 0x0F;
    ipv6.traffic_class = (first_word >> 20) & 0xFF;
    ipv6.flow_label = first_word & 0xFFFFF;
    ipv6.payload_length = ((uint16_t)packet->packet_data[offset + IPV6_PAYLOAD_LENGTH_OFFSET] << 8) | packet->packet_data[offset + IPV6_PAYLOAD_LENGTH_OFFSET + 1];
    ipv6.next_header = packet->packet_data[offset + IPV6_NEXT_HEADER_OFFSET];
    ipv6.hop_limit = packet->packet_data[offset + IPV6_HOP_LIMIT_OFFSET];
    memcpy(ipv6.source_ip, packet->packet_data + offset + IPV6_SRC_OFFSET, 16);
    memcpy(ipv6.destination_ip, packet->packet_data + offset + IPV6_DST_OFFSET, 16);
    ipv6.payload_offset = ETHERNET_HEADER_SIZE + IPV6_HEADER_SIZE;
    return ipv6;
}