#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packet_analysis.h"
#include "tcp_session_analysis.h"

void init_packet_summary(packet_summary_t *summary) {
    memset(summary, 0, sizeof(packet_summary_t));
}

void analyze_packet(
    const pcapng_t *pcapng,
    const packet_t *packet,
    const protocol_chain_t *chain,
    packet_summary_t *summary) {

    if (!chain || !summary)
        return;

    summary->total_packets++;

    const protocol_node_t *node =
        chain->root;

    while (node) {

        switch (node->type) {

        case PROTO_ETHERNET:
            summary->ethernet_packets++;
            break;

        case PROTO_IPV4: {
            summary->ipv4_packets++;

            ipv4_t *ipv4 =
                node->data;

            if (ipv4->is_fragment) {

                summary->ipv4_fragments++;

                if (ipv4->fragment_offset == 0)
                    summary->ipv4_first_fragments++;
                else
                    summary->ipv4_later_fragments++;
            }

            if (ipv4->ip_protocol ==
                IP_PROTOCOL_TCP) {

                summary->ipv4_tcp_packets++;

                if (ipv4->is_fragment) {

                    if (ipv4->fragment_offset == 0)
                        summary->ipv4_tcp_first_fragments++;
                    else
                        summary->ipv4_tcp_later_fragments++;
                }
            }

            if (ipv4->ip_protocol ==
                IP_PROTOCOL_ICMP) {

                summary->ipv4_icmp_packets++;

                if (ipv4->is_fragment) {

                    if (ipv4->fragment_offset == 0)
                        summary->ipv4_icmp_first_fragments++;
                    else
                        summary->ipv4_icmp_later_fragments++;
                }
            }

            break;
        }

        case PROTO_IPV6:
            summary->ipv6_packets++;
            break;

        case PROTO_TCP: {
            summary->tcp_packets++;

            tcp_t *tcp =
                node->data;

            if (tcp->syn && tcp->ack)
                summary->tcp_syn_ack_packets++;
            else if (tcp->syn)
                summary->tcp_syn_packets++;

            if (tcp->ack)
                summary->tcp_ack_packets++;

            if (tcp->fin)
                summary->tcp_fin_packets++;

            if (tcp->rst)
                summary->tcp_rst_packets++;

            if (tcp->psh)
                summary->tcp_psh_packets++;

            if (tcp->has_mss)
                summary->tcp_mss_options++;

            if (tcp->has_window_scale)
                summary->tcp_window_scale_options++;

            if (tcp->sack_permitted)
                summary->tcp_sack_permitted++;

            if (tcp->sack_block_count > 0)
                summary->tcp_sack_options++;

            if (tcp->has_timestamp)
                summary->tcp_timestamp_options++;

            const protocol_node_t *ipv4_node =
                chain->root;

            ipv4_t *ipv4 = NULL;

            while (ipv4_node) {

                if (ipv4_node->type ==
                    PROTO_IPV4) {

                    ipv4 =
                        ipv4_node->data;

                    break;
                }

                ipv4_node =
                    ipv4_node->next;
            }

            if (ipv4 && packet && pcapng) {

                analyze_tcp_session(
                    pcapng,
                    packet,
                    ipv4,
                    tcp,
                    summary
                );
            }

            break;
        }

        case PROTO_UDP:
            summary->udp_packets++;
            break;

        case PROTO_ICMP:
            summary->icmp_packets++;
            break;

        case PROTO_UNKNOWN:
            summary->unknown_packets++;
            break;
        }

        node = node->next;
    }
}

// void print_packet_summary(
//     const packet_summary_t *summary) {

// }

void analyze_ipv4_reassembly(
    const ipv4_reassembly_t *reassembly,
    packet_summary_t *summary) {

    summary->ipv4_fragment_groups =
        reassembly->group_count;

    for (size_t i = 0;
         i < reassembly->group_count;
         i++) {

        const ipv4_fragment_group_t *group =
            reassembly->groups[i];

        ipv4_reassembly_status_t status =
            validate_fragment_group(group);

        switch (status) {

        case IPV4_REASSEMBLY_COMPLETE:
            summary->ipv4_complete_groups++;
            break;

        case IPV4_REASSEMBLY_INCOMPLETE:
            summary->ipv4_incomplete_groups++;
            break;

        case IPV4_REASSEMBLY_OVERLAP:
            summary->ipv4_overlap_groups++;
            break;

        case IPV4_REASSEMBLY_CONFLICT:
            summary->ipv4_conflict_groups++;
            break;

        default:
            break;
        }
    }
}

void free_packet_summary(
    packet_summary_t *summary) {

    if (!summary)
        return;

    for (size_t i = 0; i < summary->tcp_session_count; i++) {

        tcp_session_t *session = &summary->tcp_sessions[i];
        free(session->direction_a_to_b.ranges);
        free(session->direction_b_to_a.ranges);
        free(session->direction_a_to_b.timestamp_samples);
        free(session->direction_b_to_a.timestamp_samples);     
        free(session->direction_a_to_b.rtt_samples);
        free(session->direction_b_to_a.rtt_samples);
    }

    free(summary->tcp_sessions);

    summary->tcp_sessions = NULL;
    summary->tcp_session_count = 0;
    summary->tcp_session_capacity = 0;
}