#ifndef TCP_SESSION_STATE_H
#define TCP_SESSION_STATE_H

#include "packet_analysis.h"

void update_tcp_state(tcp_session_t *s, tcp_direction_analysis_t *src_dir, const tcp_t *tcp);

const char *tcp_state_name(tcp_state_t state);

int tcp_state_closed(tcp_state_t state);

int tcp_state_handshake_observed(tcp_state_t state);

int tcp_state_established(tcp_state_t state);

#endif