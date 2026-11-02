#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stdint.h>
#include <stddef.h>


enum {
    ETHERNET_ETHERTYPE_IPV4 = 0x0800,
    ETHERNET_ETHERTYPE_ARP = 0x0806,
    ETHERNET_ETHERTYPE_VLAN = 0x8100,
    ETHERNET_ETHERTYPE_IPV6 = 0x86DD,
    ETHERNET_ETHERTYPE_MPLS = 0x8847,
    ETHERNET_ETHERTYPE_MPLS_MULTICAST = 0x8848,
    ETHERNET_ETHERTYPE_PPPOE_DISCOVERY = 0x8863,
    ETHERNET_ETHERTYPE_PPPOE_SESSION = 0x8864,
    ETHERNET_ETHERTYPE_LLDP = 0x88CC,
    ETHERNET_ETHERTYPE_MACSEC = 0x88E5,
    ETHERNET_ETHERTYPE_PTP = 0x88F7,
    ETHERNET_ETHERTYPE_CFM = 0x8902
};

enum {
    IP_PROTOCOL_ICMP = 1,
    IP_PROTOCOL_TCP = 6,
    IP_PROTOCOL_UDP = 17
};

static const size_t PCAPNG_ALIGNMENT = 4;
static const uint32_t PCAPNG_MAX_BLOCK_LENGTH = 10U * 1024U * 1024U;

static const uint16_t PCAPNG_OPTION_END_OF_OPTIONS = 0;
static const size_t PCAPNG_OPTION_ALIGNMENT = 4;

static const uint32_t PCAPNG_SHB_MIN_LENGTH = 28;
static const uint32_t PCAPNG_IDB_MIN_LENGTH = 20;
static const uint32_t PCAPNG_EPB_MIN_LENGTH = 32;
static const uint32_t PCAPNG_PB_MIN_LENGTH = 28;
static const uint32_t PCAPNG_SPB_MIN_LENGTH = 16;
static const uint32_t PCAPNG_NRB_MIN_LENGTH = 16;
static const uint32_t PCAPNG_ISB_MIN_LENGTH = 24;

static const uint16_t PCAPNG_MAJOR_VERSION = 1;
static const uint16_t PCAPNG_MINOR_VERSION = 0;

static const uint32_t PCAPNG_BYTE_ORDER_MAGIC_LE = 0x1A2B3C4D;
static const uint32_t PCAPNG_BYTE_ORDER_MAGIC_BE = 0x4D3C2B1A;

static const uint32_t PCAPNG_BLOCK_OVERHEAD = 12;
static const uint32_t PCAPNG_BLOCK_HEADER_SIZE = 8;
static const uint32_t PCAPNG_BLOCK_FOOTER_SIZE = 4;

static const uint32_t PCAPNG_TIMESTAMP_SIZE = 8;
static const uint32_t PCAPNG_PACKET_LENGTH_FIELD_SIZE = 4;

static const uint32_t PCAPNG_MAX_UINT16 = 0xFFFFU;
static const uint64_t PCAPNG_MAX_UINT32 = 0xFFFFFFFFULL;


/*
 * Ethernet
 */
static const size_t ETHERNET_HEADER_SIZE = 14;
static const size_t ETHERNET_MAC_ADDRESS_SIZE = 6;

static const size_t ETHERNET_DST_MAC_OFFSET = 0;
static const size_t ETHERNET_SRC_MAC_OFFSET = 6;
static const size_t ETHERNET_ETHERTYPE_OFFSET = 12;


/*
 * IPv4
 */
static const uint8_t IPV4_VERSION_SHIFT = 4;
static const uint8_t IPV4_IHL_MASK = 0x0F;

static const size_t IPV4_VERSION_OFFSET = 0;
static const size_t IPV4_TOS_OFFSET = 1;
static const size_t IPV4_TOTAL_LENGTH_OFFSET = 2;
static const size_t IPV4_IDENTIFICATION_OFFSET = 4;
static const size_t IPV4_FLAGS_OFFSET = 6;
static const size_t IPV4_TTL_OFFSET = 8;
static const size_t IPV4_PROTOCOL_OFFSET = 9;
static const size_t IPV4_CHECKSUM_OFFSET = 10;
static const size_t IPV4_SRC_OFFSET = 12;
static const size_t IPV4_DST_OFFSET = 16;

static const size_t IPV4_HEADER_SIZE = 20;

static const uint16_t IPV4_FRAGMENT_OFFSET_MASK = 0x1FFF;
static const uint16_t IPV4_MORE_FRAGMENTS_FLAG = 0x2000;
static const size_t IPV4_FRAGMENT_ALIGNMENT = 8;


/*
 * IPv6
 */
static const size_t IPV6_VERSION_OFFSET = 0;
static const uint8_t IPV6_VERSION_SHIFT = 4;

static const size_t IPV6_TRAFFIC_CLASS_OFFSET = 1;
static const uint8_t IPV6_TRAFFIC_CLASS_MASK_HIGH = 0x0F;
static const uint8_t IPV6_TRAFFIC_CLASS_SHIFT = 4;

static const size_t IPV6_FLOW_LABEL_OFFSET = 1;
static const uint32_t IPV6_FLOW_LABEL_MASK = 0x0F;

static const size_t IPV6_PAYLOAD_LENGTH_OFFSET = 4;
static const size_t IPV6_NEXT_HEADER_OFFSET = 6;
static const size_t IPV6_HOP_LIMIT_OFFSET = 7;

static const size_t IPV6_SRC_OFFSET = 8;
static const size_t IPV6_DST_OFFSET = 24;

static const size_t IPV6_HEADER_SIZE = 40;


/*
 * TCP
 */
static const size_t TCP_SOURCE_PORT_OFFSET = 0;
static const size_t TCP_DESTINATION_PORT_OFFSET = 2;
static const size_t TCP_SEQUENCE_NUMBER_OFFSET = 4;
static const size_t TCP_ACKNOWLEDGMENT_NUMBER_OFFSET = 8;

static const size_t TCP_DATA_OFFSET = 12;
static const uint8_t TCP_DATA_OFFSET_SHIFT = 4;
static const uint8_t TCP_DATA_OFFSET_MASK = 0x0F;

static const size_t TCP_FLAGS_OFFSET = 13;

static const size_t TCP_WINDOW_SIZE_OFFSET = 14;
static const size_t TCP_CHECKSUM_OFFSET = 16;
static const size_t TCP_URGENT_POINTER_OFFSET = 18;

static const size_t TCP_HEADER_MIN_SIZE = 20;

static const uint8_t TCP_NS_MASK = 0x01;

static const uint8_t TCP_CWR_MASK = 0x80;
static const uint8_t TCP_ECE_MASK = 0x40;
static const uint8_t TCP_URG_MASK = 0x20;
static const uint8_t TCP_ACK_MASK = 0x10;
static const uint8_t TCP_PSH_MASK = 0x08;
static const uint8_t TCP_RST_MASK = 0x04;
static const uint8_t TCP_SYN_MASK = 0x02;
static const uint8_t TCP_FIN_MASK = 0x01;

/*
 * TCP options
 */
static const uint8_t TCP_OPTION_EOL = 0;
static const uint8_t TCP_OPTION_NOP = 1;
static const uint8_t TCP_OPTION_MSS = 2;
static const uint8_t TCP_OPTION_WINDOW_SCALE = 3;
static const uint8_t TCP_OPTION_SACK_PERMITTED = 4;
static const uint8_t TCP_OPTION_SACK = 5;
static const uint8_t TCP_OPTION_TIMESTAMP = 8;

static const uint8_t TCP_OPTION_MSS_LENGTH = 4;
static const uint8_t TCP_OPTION_WINDOW_SCALE_LENGTH = 3;
static const uint8_t TCP_OPTION_SACK_PERMITTED_LENGTH = 2;
static const uint8_t TCP_OPTION_TIMESTAMP_LENGTH = 10;
static const uint8_t TCP_OPTION_SACK_BLOCK_LENGTH = 8;

/*
 * UDP
 */
static const size_t UDP_HEADER_SIZE = 8;

static const size_t UDP_SOURCE_PORT_OFFSET = 0;
static const size_t UDP_DESTINATION_PORT_OFFSET = 2;
static const size_t UDP_LENGTH_OFFSET = 4;
static const size_t UDP_CHECKSUM_OFFSET = 6;


/*
 * ICMP
 */
static const size_t ICMP_HEADER_SIZE = 8;

static const size_t ICMP_TYPE_OFFSET = 0;
static const size_t ICMP_CODE_OFFSET = 1;
static const size_t ICMP_CHECKSUM_OFFSET = 2;
static const size_t ICMP_REST_OF_HEADER_OFFSET = 4;


#endif