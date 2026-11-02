#include "tcp_session_analysis.h"

void analyze_tcp_session(const pcapng_t *pcapng,
                         const packet_t *packet,
                         const ipv4_t *ipv4,
                         const tcp_t *tcp,
                         packet_summary_t *summary)
{
    tcp_session_t *s =
        find_tcp_session(summary, ipv4, tcp);

    if (!s) {
        s = create_tcp_session(summary, ipv4, tcp);

        if (!s)
            return;
    }

    tcp_session_endpoint_t *endpoint =
        get_tcp_endpoint(s, ipv4, tcp);

    tcp_direction_analysis_t *src_dir =
        get_tcp_direction(s, ipv4, tcp);

    tcp_direction_analysis_t *ack_dir =
        (src_dir == &s->direction_a_to_b)
            ? &s->direction_b_to_a
            : &s->direction_a_to_b;

    double ts =
        get_packet_timestamp(pcapng, packet);

    s->packets++;
    s->payload_bytes += tcp->payload_length;

    if (src_dir == &s->direction_a_to_b) {
        s->packets_a_to_b++;
        s->payload_bytes_a_to_b +=
            tcp->payload_length;
    } else {
        s->packets_b_to_a++;
        s->payload_bytes_b_to_a +=
            tcp->payload_length;
    }

    if (tcp->syn && tcp->ack)
        s->syn_ack_packets++;
    else if (tcp->syn)
        s->syn_packets++;

    if (tcp->ack)
        s->ack_packets++;

    if (tcp->fin)
        s->fin_packets++;

    if (tcp->rst)
        s->rst_packets++;

    if (tcp->psh)
        s->psh_packets++;

    if (tcp->sack_block_count > 0)
        s->sack_packets++;

    if (tcp->has_timestamp)
        s->timestamp_packets++;

    if (tcp->syn && !tcp->ack) {
        s->client_known = 1;
        s->client_is_a =
            (src_dir == &s->direction_a_to_b);
    }

    update_tcp_state(s, src_dir, tcp);
    update_tcp_endpoint(endpoint, tcp);

    analyze_tcp_sequence(src_dir, tcp, ts);
    analyze_tcp_ack(ack_dir, tcp, ts);
    analyze_tcp_timestamp(
        src_dir,
        ack_dir,
        tcp,
        ts);
}