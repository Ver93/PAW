#ifndef TCP_TIMESTAMP_ANALYSIS_H
#define TCP_TIMESTAMP_ANALYSIS_H

#include "packet_analysis.h"

void analyze_tcp_timestamp(
    tcp_direction_analysis_t *source_direction,
    tcp_direction_analysis_t *echoed_direction,
    const tcp_t *tcp,
    double timestamp);

void print_tcp_timestamp_rtt_analysis(
    const tcp_direction_analysis_t *direction);

#endif