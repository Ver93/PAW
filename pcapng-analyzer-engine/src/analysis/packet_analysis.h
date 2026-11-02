#ifndef PACKET_ANALYSIS_H

#define PACKET_ANALYSIS_H

#include <stddef.h>
#include <stdint.h>

#include "protocol_node.h"
#include "pcapng.h"
#include "ipv4_reassembly.h"
#include "ipv4_reassembly_validation.h"

typedef enum {
    TCP_STATE_OBSERVED = 0,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_ESTABLISHED_INFERRED,
    TCP_STATE_DATA_OBSERVED,
    TCP_STATE_FIN_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_CLOSED_FIN,
    TCP_STATE_CLOSED_RST
} tcp_state_t;

typedef struct {
    uint8_t ip[4];
    uint16_t port;
    size_t packets;
    size_t payload_bytes;
    size_t ack_packets;
    size_t psh_packets;
    size_t fin_packets;
    size_t rst_packets;
    size_t sack_packets;
    size_t timestamp_packets;
    int has_mss;
    uint16_t maximum_segment_size;
    int has_window_scale;
    uint8_t window_scale;
    int sack_permitted;
} tcp_session_endpoint_t;

typedef struct {
    uint32_t sequence_start;
    uint32_t sequence_end;
} tcp_sequence_range_t;

typedef struct {
    uint32_t sequence_start;
    uint32_t sequence_end;
    double timestamp;
    int retransmitted;
    int acknowledged;
} tcp_rtt_segment_t;

typedef struct {
    uint32_t timestamp_value;
    double timestamp_time;
    int matched;
} tcp_timestamp_sample_t;

typedef struct {
    uint32_t next_sequence;
    int sequence_initialized;

    uint32_t highest_sequence;
    int highest_sequence_initialized;

    uint32_t last_acknowledgment;
    int acknowledgment_initialized;

    size_t retransmissions;
    size_t out_of_order;
    size_t sequence_gaps;
    size_t duplicate_acks;

    tcp_sequence_range_t *ranges;
    size_t range_count;
    size_t range_capacity;

    tcp_rtt_segment_t rtt_probe;
    int rtt_probe_initialized;

    tcp_timestamp_sample_t *timestamp_samples;
    size_t timestamp_sample_count;
    size_t timestamp_sample_capacity;

    double *rtt_samples;
    size_t rtt_sample_count;
    size_t rtt_sample_capacity;

    double rtt_min;
    double rtt_max;
    double rtt_sum;

    double rtt_median;
    double rtt_p95;
    double rtt_p99;

    size_t tcp_timestamp_rtt_sample_count;
    double tcp_timestamp_rtt_min;
    double tcp_timestamp_rtt_max;
    double tcp_timestamp_rtt_sum;
} tcp_direction_analysis_t;

typedef struct {
    tcp_session_endpoint_t endpoint_a;
    tcp_session_endpoint_t endpoint_b;

    size_t packets;
    size_t payload_bytes;

    size_t packets_a_to_b;
    size_t packets_b_to_a;

    size_t payload_bytes_a_to_b;
    size_t payload_bytes_b_to_a;

    size_t syn_packets;
    size_t syn_ack_packets;
    size_t ack_packets;
    size_t fin_packets;
    size_t rst_packets;
    size_t psh_packets;
    size_t sack_packets;
    size_t timestamp_packets;

    int client_known;
    int client_is_a;

    int fin_a_seen;
    int fin_b_seen;
    int fin_a_acknowledged;
    int fin_b_acknowledged;

    tcp_direction_analysis_t direction_a_to_b;
    tcp_direction_analysis_t direction_b_to_a;

    tcp_state_t state;
} tcp_session_t;

typedef struct {
    size_t total_packets;
    size_t ethernet_packets;

    size_t ipv4_packets;
    size_t ipv4_tcp_packets;
    size_t ipv4_tcp_first_fragments;
    size_t ipv4_tcp_later_fragments;

    size_t ipv4_icmp_packets;
    size_t ipv4_icmp_first_fragments;
    size_t ipv4_icmp_later_fragments;

    size_t ipv6_packets;

    size_t tcp_packets;
    size_t tcp_syn_packets;
    size_t tcp_syn_ack_packets;
    size_t tcp_ack_packets;
    size_t tcp_fin_packets;
    size_t tcp_rst_packets;
    size_t tcp_psh_packets;

    size_t tcp_mss_options;
    size_t tcp_window_scale_options;
    size_t tcp_sack_permitted;
    size_t tcp_sack_options;
    size_t tcp_timestamp_options;

    size_t udp_packets;
    size_t icmp_packets;
    size_t unknown_packets;

    size_t ipv4_fragments;
    size_t ipv4_first_fragments;
    size_t ipv4_later_fragments;

    size_t ipv4_fragment_groups;
    size_t ipv4_complete_groups;
    size_t ipv4_incomplete_groups;
    size_t ipv4_overlap_groups;
    size_t ipv4_conflict_groups;

    tcp_session_t *tcp_sessions;
    size_t tcp_session_count;
    size_t tcp_session_capacity;
} packet_summary_t;

void init_packet_summary(packet_summary_t *summary);

void analyze_packet(const pcapng_t *pcapng,
                    const packet_t *packet,
                    const protocol_chain_t *chain,
                    packet_summary_t *summary);

// void print_packet_summary(const packet_summary_t *summary);

void print_tcp_sessions(const packet_summary_t *summary);

void free_packet_summary(packet_summary_t *summary);

void analyze_ipv4_reassembly(const ipv4_reassembly_t *reassembly,
                             packet_summary_t *summary);

#endif