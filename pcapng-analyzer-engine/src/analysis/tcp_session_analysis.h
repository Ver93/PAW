#ifndef TCP_SESSION_ANALYSIS_H
#define TCP_SESSION_ANALYSIS_H

#include "packet_analysis.h"
// #include "pcapng_blocks.h"
#include "tcp_session_analysis.h"
#include "tcp_session.h"
#include "tcp_session_state.h"
#include "tcp_sequence_analysis.h"
#include "tcp_rtt_analysis.h"
#include "tcp_timestamp_analysis.h"

void analyze_tcp_session(
    const pcapng_t *pcapng,
    const packet_t *packet,
    const ipv4_t *ipv4,
    const tcp_t *tcp,
    packet_summary_t *summary);

void print_tcp_sessions(
    const packet_summary_t *summary);

#endif