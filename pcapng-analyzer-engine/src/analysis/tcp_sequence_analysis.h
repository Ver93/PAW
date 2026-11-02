#ifndef TCP_SEQUENCE_ANALYSIS_H
#define TCP_SEQUENCE_ANALYSIS_H

#include <stdlib.h>
#include <stdint.h>

#include "tcp_sequence_analysis.h"
#include "tcp_rtt_analysis.h"

void analyze_tcp_sequence(
    tcp_direction_analysis_t *direction,
    const tcp_t *tcp,
    double timestamp);
#endif