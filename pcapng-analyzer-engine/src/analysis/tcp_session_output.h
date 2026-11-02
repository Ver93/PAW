#ifndef TCP_SESSION_OUTPUT_H
#define TCP_SESSION_OUTPUT_H

#include "packet_analysis.h"
#include "tcp_rtt_analysis.h"
#include "tcp_timestamp_analysis.h"

void print_tcp_sessions(const packet_summary_t *summary);

#endif