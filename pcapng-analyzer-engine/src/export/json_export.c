#include "json_export.h"

void print_protocol_nodes_json(
    const protocol_chain_t *chain,
    size_t packet_index
) {
    if (!chain)
        return;

    const protocol_node_t *node = chain->root;

    while (node) {

        switch (node->type) {

        case PROTO_ETHERNET: {
            ethernet_t *eth = node->data;

            printf(
                "{\"packet\":%zu,"
                "\"type\":\"Ethernet\","
                "\"sourceMac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
                "\"destinationMac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
                "\"etherType\":%u}\n",

                packet_index,

                eth->src_mac[0],
                eth->src_mac[1],
                eth->src_mac[2],
                eth->src_mac[3],
                eth->src_mac[4],
                eth->src_mac[5],

                eth->dst_mac[0],
                eth->dst_mac[1],
                eth->dst_mac[2],
                eth->dst_mac[3],
                eth->dst_mac[4],
                eth->dst_mac[5],

                eth->ether_type
            );

            break;
        }

        case PROTO_IPV4: {
            ipv4_t *ipv4 = node->data;

            printf(
                "{\"packet\":%zu,"
                "\"type\":\"IPv4\","
                "\"version\":%u,"
                "\"ihl\":%u,"
                "\"headerLength\":%u,"
                "\"tos\":%u,"
                "\"totalLength\":%u,"
                "\"identification\":%u,"
                "\"reservedFlag\":%d,"
                "\"dontFragment\":%d,"
                "\"moreFragments\":%d,"
                "\"fragmentOffset\":%u,"
                "\"ttl\":%u,"
                "\"protocol\":%u,"
                "\"checksum\":%u,"
                "\"source\":\"%u.%u.%u.%u\","
                "\"destination\":\"%u.%u.%u.%u\","
                "\"isFragment\":%d,"
                "\"payloadOffset\":%zu,"
                "\"payloadLength\":%zu}\n",

                packet_index,

                ipv4->ip_version,
                ipv4->ihl,
                ipv4->ihl * 4,
                ipv4->tos,
                ipv4->total_length,
                ipv4->ip_identification,

                ipv4->reserved_flag,
                ipv4->dont_fragment,
                ipv4->more_fragments,
                ipv4->fragment_offset,

                ipv4->ttl,
                ipv4->ip_protocol,
                ipv4->header_checksum,

                ipv4->source_ip[0],
                ipv4->source_ip[1],
                ipv4->source_ip[2],
                ipv4->source_ip[3],

                ipv4->destination_ip[0],
                ipv4->destination_ip[1],
                ipv4->destination_ip[2],
                ipv4->destination_ip[3],

                ipv4->is_fragment,
                ipv4->payload_offset,
                ipv4->payload_length
            );

            break;
        }

        case PROTO_IPV6: {
            ipv6_t *ipv6 = node->data;

            printf(
                "{\"packet\":%zu,"
                "\"type\":\"IPv6\","
                "\"version\":%u,"
                "\"trafficClass\":%u,"
                "\"flowLabel\":%u,"
                "\"payloadLength\":%u,"
                "\"nextHeader\":%u,"
                "\"hopLimit\":%u,"
                "\"source\":\"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\","
                "\"destination\":\"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\"}\n",

                packet_index,

                ipv6->ip_version,
                ipv6->traffic_class,
                ipv6->flow_label,
                ipv6->payload_length,
                ipv6->next_header,
                ipv6->hop_limit,

                ipv6->source_ip[0],
                ipv6->source_ip[1],
                ipv6->source_ip[2],
                ipv6->source_ip[3],
                ipv6->source_ip[4],
                ipv6->source_ip[5],
                ipv6->source_ip[6],
                ipv6->source_ip[7],
                ipv6->source_ip[8],
                ipv6->source_ip[9],
                ipv6->source_ip[10],
                ipv6->source_ip[11],
                ipv6->source_ip[12],
                ipv6->source_ip[13],
                ipv6->source_ip[14],
                ipv6->source_ip[15],

                ipv6->destination_ip[0],
                ipv6->destination_ip[1],
                ipv6->destination_ip[2],
                ipv6->destination_ip[3],
                ipv6->destination_ip[4],
                ipv6->destination_ip[5],
                ipv6->destination_ip[6],
                ipv6->destination_ip[7],
                ipv6->destination_ip[8],
                ipv6->destination_ip[9],
                ipv6->destination_ip[10],
                ipv6->destination_ip[11],
                ipv6->destination_ip[12],
                ipv6->destination_ip[13],
                ipv6->destination_ip[14],
                ipv6->destination_ip[15]
            );

            break;
        }

        case PROTO_TCP: {
            tcp_t *tcp = node->data;

            printf(
                "{\"packet\":%zu,"
                "\"type\":\"TCP\","
                "\"sourcePort\":%u,"
                "\"destinationPort\":%u,"
                "\"sequenceNumber\":%u,"
                "\"acknowledgmentNumber\":%u,"
                "\"headerLength\":%u,"
                "\"ns\":%u,"
                "\"cwr\":%u,"
                "\"ece\":%u,"
                "\"urg\":%u,"
                "\"ack\":%u,"
                "\"psh\":%u,"
                "\"rst\":%u,"
                "\"syn\":%u,"
                "\"fin\":%u,"
                "\"windowSize\":%u,"
                "\"checksum\":%u,"
                "\"urgentPointer\":%u,"
                "\"hasMss\":%d,"
                "\"maximumSegmentSize\":%u,"
                "\"hasWindowScale\":%d,"
                "\"windowScale\":%u,"
                "\"sackPermitted\":%d,"
                "\"sackBlockCount\":%zu,"
                "\"hasTimestamp\":%d,"
                "\"timestampValue\":%u,"
                "\"timestampEchoReply\":%u,"
                "\"payloadOffset\":%zu,"
                "\"payloadLength\":%zu}\n",

                packet_index,

                tcp->source_port,
                tcp->destination_port,

                tcp->sequence_number,
                tcp->acknowledgment_number,

                tcp->data_offset * 4,

                tcp->ns,
                tcp->cwr,
                tcp->ece,
                tcp->urg,
                tcp->ack,
                tcp->psh,
                tcp->rst,
                tcp->syn,
                tcp->fin,

                tcp->window_size,
                tcp->checksum,
                tcp->urgent_pointer,

                tcp->has_mss,
                tcp->maximum_segment_size,

                tcp->has_window_scale,
                tcp->window_scale,

                tcp->sack_permitted,
                tcp->sack_block_count,

                tcp->has_timestamp,
                tcp->timestamp_value,
                tcp->timestamp_echo_reply,

                tcp->payload_offset,
                tcp->payload_length
            );

            break;
        }

        case PROTO_UDP: {
            udp_t *udp = node->data;

            printf(
                "{\"packet\":%zu,"
                "\"type\":\"UDP\","
                "\"sourcePort\":%u,"
                "\"destinationPort\":%u,"
                "\"length\":%u,"
                "\"checksum\":%u,"
                "\"payloadOffset\":%zu,"
                "\"payloadLength\":%zu}\n",

                packet_index,

                udp->source_port,
                udp->destination_port,
                udp->length,
                udp->checksum,
                udp->payload_offset,
                udp->payload_length
            );

            break;
        }

        case PROTO_ICMP: {
            icmp_t *icmp = node->data;

            printf(
                "{\"packet\":%zu,"
                "\"type\":\"ICMP\","
                "\"icmpType\":%u,"
                "\"code\":%u,"
                "\"checksum\":%u,"
                "\"restOfHeader\":%u,"
                "\"payloadOffset\":%zu,"
                "\"payloadLength\":%zu}\n",

                packet_index,

                icmp->type,
                icmp->code,
                icmp->checksum,
                icmp->rest_of_header,
                icmp->payload_offset,
                icmp->payload_length
            );

            break;
        }

        case PROTO_HTTP:
            printf(
                "{\"packet\":%zu,\"type\":\"HTTP\"}\n",
                packet_index
            );
            break;

        case PROTO_HTTPS:
            printf(
                "{\"packet\":%zu,\"type\":\"HTTPS\"}\n",
                packet_index
            );
            break;

        case PROTO_DNS:
            printf(
                "{\"packet\":%zu,\"type\":\"DNS\"}\n",
                packet_index
            );
            break;

        case PROTO_FTP:
            printf(
                "{\"packet\":%zu,\"type\":\"FTP\"}\n",
                packet_index
            );
            break;

        case PROTO_SSH:
            printf(
                "{\"packet\":%zu,\"type\":\"SSH\"}\n",
                packet_index
            );
            break;

        case PROTO_SMTP:
            printf(
                "{\"packet\":%zu,\"type\":\"SMTP\"}\n",
                packet_index
            );
            break;

        case PROTO_IMAP:
            printf(
                "{\"packet\":%zu,\"type\":\"IMAP\"}\n",
                packet_index
            );
            break;

        case PROTO_DHCP:
            printf(
                "{\"packet\":%zu,\"type\":\"DHCP\"}\n",
                packet_index
            );
            break;

        default:
            break;
        }

        node = node->next;
    }
}