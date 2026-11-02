#include "ipv4_parser.h"

ipv4_t parse_ipv4(const packet_t *packet) {
    ipv4_t ipv4 = {0};
    ipv4.ip_payload_offset = ETHERNET_HEADER_SIZE;
    ipv4.ip_version = packet->packet_data[ipv4.ip_payload_offset + IPV4_VERSION_OFFSET] >> IPV4_VERSION_SHIFT;
    ipv4.ihl = packet->packet_data[ipv4.ip_payload_offset + IPV4_VERSION_OFFSET] & IPV4_IHL_MASK;
    ipv4.tos = packet->packet_data[ipv4.ip_payload_offset + IPV4_TOS_OFFSET];
    ipv4.total_length = ((uint16_t)packet->packet_data[ipv4.ip_payload_offset + IPV4_TOTAL_LENGTH_OFFSET] << 8) | packet->packet_data[ipv4.ip_payload_offset + IPV4_TOTAL_LENGTH_OFFSET + 1];
    ipv4.ip_identification = ((uint16_t)packet->packet_data[ipv4.ip_payload_offset + IPV4_IDENTIFICATION_OFFSET] << 8) | packet->packet_data[ipv4.ip_payload_offset + IPV4_IDENTIFICATION_OFFSET + 1];
    uint16_t flags_fragment = ((uint16_t)packet->packet_data[ipv4.ip_payload_offset + IPV4_FLAGS_OFFSET] << 8) | packet->packet_data[ipv4.ip_payload_offset + IPV4_FLAGS_OFFSET + 1];
    ipv4.reserved_flag = (flags_fragment >> 15) & 0x01;
    ipv4.dont_fragment = (flags_fragment >> 14) & 0x01;
    ipv4.more_fragments = (flags_fragment >> 13) & 0x01;
    ipv4.fragment_offset = flags_fragment & IPV4_FRAGMENT_OFFSET_MASK;
    ipv4.is_fragment = ipv4.more_fragments || ipv4.fragment_offset != 0;
    ipv4.ttl = packet->packet_data[ipv4.ip_payload_offset + IPV4_TTL_OFFSET];
    ipv4.ip_protocol = packet->packet_data[ipv4.ip_payload_offset + IPV4_PROTOCOL_OFFSET];
    ipv4.header_checksum = ((uint16_t)packet->packet_data[ipv4.ip_payload_offset + IPV4_CHECKSUM_OFFSET] << 8) | packet->packet_data[ipv4.ip_payload_offset + IPV4_CHECKSUM_OFFSET + 1];
    memcpy(ipv4.source_ip, packet->packet_data + ipv4.ip_payload_offset + IPV4_SRC_OFFSET, 4);
    memcpy(ipv4.destination_ip, packet->packet_data + ipv4.ip_payload_offset + IPV4_DST_OFFSET, 4);
    ipv4.ip_payload_offset = ETHERNET_HEADER_SIZE + (ipv4.ihl * 4);
    ipv4.ip_payload_length = ipv4.total_length - (ipv4.ihl * 4);
    ipv4.payload_offset = ipv4.ip_payload_offset;
    ipv4.payload_length = ipv4.ip_payload_length;
    return ipv4;
}