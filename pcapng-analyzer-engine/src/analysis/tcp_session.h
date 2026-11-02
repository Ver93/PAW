#ifndef TCP_SESSION_H
#define TCP_SESSION_H

#include "packet_analysis.h"

tcp_session_t *find_tcp_session(packet_summary_t *summary, const ipv4_t *ipv4, const tcp_t *tcp);

tcp_session_t *create_tcp_session(packet_summary_t *summary, const ipv4_t *ipv4, const tcp_t *tcp);

tcp_session_endpoint_t *get_tcp_endpoint(tcp_session_t *s, const ipv4_t *ipv4, const tcp_t *tcp);

tcp_direction_analysis_t *get_tcp_direction(tcp_session_t *s, const ipv4_t *ipv4, const tcp_t *tcp);

void update_tcp_endpoint(tcp_session_endpoint_t *e, const tcp_t *tcp);

double get_packet_timestamp(const pcapng_t *pcapng, const packet_t *packet);

#endif