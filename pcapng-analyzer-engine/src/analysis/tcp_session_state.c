#include "tcp_session_state.h"

static void update_fin_state(
    tcp_session_t *s,
    tcp_direction_analysis_t *src_dir,
    const tcp_t *tcp)
{
    if (!tcp->fin)
        return;

    if (src_dir == &s->direction_a_to_b)
        s->fin_a_seen = 1;
    else
        s->fin_b_seen = 1;

    if (s->fin_a_seen && s->fin_b_seen)
        s->state = TCP_STATE_CLOSING;
    else
        s->state = TCP_STATE_FIN_WAIT;
}

static void update_fin_acknowledgment(
    tcp_session_t *s,
    tcp_direction_analysis_t *src_dir,
    const tcp_t *tcp)
{
    if (!tcp->ack)
        return;

    /*
     * ACK from B can acknowledge A's FIN.
     */
    if (src_dir == &s->direction_b_to_a &&
        s->fin_a_seen)
        s->fin_a_acknowledged = 1;

    /*
     * ACK from A can acknowledge B's FIN.
     */
    if (src_dir == &s->direction_a_to_b &&
        s->fin_b_seen)
        s->fin_b_acknowledged = 1;

    if (s->fin_a_seen &&
        s->fin_b_seen &&
        s->fin_a_acknowledged &&
        s->fin_b_acknowledged)
        s->state = TCP_STATE_CLOSED_FIN;
}

void update_tcp_state(tcp_session_t *s,
                      tcp_direction_analysis_t *src_dir,
                      const tcp_t *tcp)
{
    /*
     * RST aborts the session regardless
     * of the previous observed state.
     */
    if (tcp->rst) {
        s->state = TCP_STATE_CLOSED_RST;
        return;
    }

    /*
     * Once a FIN-based close has completed,
     * normal ACK/data packets must not reopen
     * the session.
     */
    if (s->state == TCP_STATE_CLOSED_FIN ||
        s->state == TCP_STATE_CLOSED_RST)
        return;

    /*
     * FIN handling must happen before ordinary
     * ACK handling.
     */
    if (tcp->fin) {
        update_fin_state(s, src_dir, tcp);
        return;
    }

    /*
     * ACK may acknowledge a previously observed FIN.
     */
    if (s->fin_a_seen || s->fin_b_seen) {
        update_fin_acknowledgment(s, src_dir, tcp);

        if (s->state == TCP_STATE_CLOSED_FIN)
            return;
    }

    /*
     * Normal three-way handshake.
     */
    if (tcp->syn && !tcp->ack) {
        s->state = TCP_STATE_SYN_SENT;
        return;
    }

    if (tcp->syn && tcp->ack) {
        s->state = TCP_STATE_SYN_RECEIVED;
        return;
    }

    if (tcp->ack &&
        s->state == TCP_STATE_SYN_RECEIVED) {
        s->state = TCP_STATE_ESTABLISHED;
        return;
    }

    /*
     * If no SYN was observed and this is the first
     * normal ACK/data packet, do not immediately
     * claim that the connection was established.
     */
    if (s->state == TCP_STATE_OBSERVED &&
        (tcp->ack || tcp->payload_length > 0)) {
        s->state = TCP_STATE_DATA_OBSERVED;
        return;
    }

    /*
     * More normal TCP traffic after an initial data
     * observation gives stronger evidence that the
     * connection was already established when capture
     * began.
     */
    if (s->state == TCP_STATE_DATA_OBSERVED &&
        (tcp->ack || tcp->payload_length > 0)) {
        s->state = TCP_STATE_ESTABLISHED_INFERRED;
        return;
    }
}

const char *tcp_state_name(tcp_state_t state)
{
    switch (state) {
    case TCP_STATE_OBSERVED:
        return "observed";

    case TCP_STATE_SYN_SENT:
        return "syn-sent";

    case TCP_STATE_SYN_RECEIVED:
        return "syn-received";

    case TCP_STATE_ESTABLISHED:
        return "established";

    case TCP_STATE_ESTABLISHED_INFERRED:
        return "established-inferred";

    case TCP_STATE_DATA_OBSERVED:
        return "data-observed";

    case TCP_STATE_FIN_WAIT:
        return "fin-wait";

    case TCP_STATE_CLOSING:
        return "closing";

    case TCP_STATE_CLOSED_FIN:
        return "closed-fin";

    case TCP_STATE_CLOSED_RST:
        return "closed-rst";

    default:
        return "unknown";
    }
}

int tcp_state_closed(tcp_state_t state)
{
    return state == TCP_STATE_CLOSED_FIN ||
           state == TCP_STATE_CLOSED_RST;
}

int tcp_state_handshake_observed(tcp_state_t state)
{
    return state == TCP_STATE_SYN_SENT ||
           state == TCP_STATE_SYN_RECEIVED ||
           state == TCP_STATE_ESTABLISHED;
}

int tcp_state_established(tcp_state_t state)
{
    return state == TCP_STATE_ESTABLISHED ||
           state == TCP_STATE_ESTABLISHED_INFERRED ||
           state == TCP_STATE_FIN_WAIT ||
           state == TCP_STATE_CLOSING ||
           state == TCP_STATE_CLOSED_FIN;
}