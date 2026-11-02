#ifndef TCP_RTT_ANALYSIS_H
#define TCP_RTT_ANALYSIS_H

#include "packet_analysis.h"
#include "tcp.h"

void analyze_tcp_ack(
    tcp_direction_analysis_t *direction,
    const tcp_t *tcp,
    double timestamp);

void update_tcp_rtt_statistics(
    tcp_direction_analysis_t *direction,
    double rtt);

void print_tcp_rtt_analysis(
    const tcp_direction_analysis_t *direction);

#endif