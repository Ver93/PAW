#include "ethernet_parser.h"

ethernet_t parse_ethernet(const packet_t *packet) {
    ethernet_t eth = {0};
    memcpy(eth.dst_mac, packet->packet_data + ETHERNET_DST_MAC_OFFSET, ETHERNET_MAC_ADDRESS_SIZE);
    memcpy(eth.src_mac, packet->packet_data + ETHERNET_SRC_MAC_OFFSET, ETHERNET_MAC_ADDRESS_SIZE);
    eth.ether_type = ((uint16_t)packet->packet_data[ETHERNET_ETHERTYPE_OFFSET] << 8) | packet->packet_data[ETHERNET_ETHERTYPE_OFFSET + 1];
    return eth;
}