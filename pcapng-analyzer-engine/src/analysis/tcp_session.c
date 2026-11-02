#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "tcp_session.h"

static int same_endpoint(const tcp_session_endpoint_t *e,
                         const uint8_t ip[4],
                         uint16_t port)
{
    return memcmp(e->ip, ip, 4) == 0 &&
           e->port == port;
}

tcp_session_t *find_tcp_session(packet_summary_t *summary,
                                const ipv4_t *ipv4,
                                const tcp_t *tcp)
{
    for (size_t i = 0; i < summary->tcp_session_count; i++) {
        tcp_session_t *s = &summary->tcp_sessions[i];

        if (same_endpoint(&s->endpoint_a,
                          ipv4->source_ip,
                          tcp->source_port) &&
            same_endpoint(&s->endpoint_b,
                          ipv4->destination_ip,
                          tcp->destination_port))
            return s;

        if (same_endpoint(&s->endpoint_a,
                          ipv4->destination_ip,
                          tcp->destination_port) &&
            same_endpoint(&s->endpoint_b,
                          ipv4->source_ip,
                          tcp->source_port))
            return s;
    }

    return NULL;
}

tcp_session_t *create_tcp_session(packet_summary_t *summary,
                                  const ipv4_t *ipv4,
                                  const tcp_t *tcp)
{
    if (summary->tcp_session_count >=
        summary->tcp_session_capacity) {

        size_t new_capacity =
            summary->tcp_session_capacity == 0
                ? 8
                : summary->tcp_session_capacity * 2;

        tcp_session_t *tmp =
            realloc(summary->tcp_sessions,
                    new_capacity * sizeof(tcp_session_t));

        if (!tmp)
            return NULL;

        summary->tcp_sessions = tmp;
        summary->tcp_session_capacity = new_capacity;
    }

    tcp_session_t *s =
        &summary->tcp_sessions[summary->tcp_session_count++];

    memset(s, 0, sizeof(tcp_session_t));

    memcpy(s->endpoint_a.ip,
           ipv4->source_ip,
           4);

    s->endpoint_a.port =
        tcp->source_port;

    memcpy(s->endpoint_b.ip,
           ipv4->destination_ip,
           4);

    s->endpoint_b.port =
        tcp->destination_port;

    s->state = TCP_STATE_OBSERVED;

    if (tcp->syn && !tcp->ack) {
        s->client_known = 1;
        s->client_is_a = 1;
    }

    return s;
}

tcp_session_endpoint_t *get_tcp_endpoint(
    tcp_session_t *s,
    const ipv4_t *ipv4,
    const tcp_t *tcp)
{
    return same_endpoint(&s->endpoint_a,
                         ipv4->source_ip,
                         tcp->source_port)
        ? &s->endpoint_a
        : &s->endpoint_b;
}

tcp_direction_analysis_t *get_tcp_direction(
    tcp_session_t *s,
    const ipv4_t *ipv4,
    const tcp_t *tcp)
{
    return same_endpoint(&s->endpoint_a,
                         ipv4->source_ip,
                         tcp->source_port)
        ? &s->direction_a_to_b
        : &s->direction_b_to_a;
}

void update_tcp_endpoint(tcp_session_endpoint_t *e,
                         const tcp_t *tcp)
{
    e->packets++;
    e->payload_bytes += tcp->payload_length;

    if (tcp->ack)
        e->ack_packets++;

    if (tcp->psh)
        e->psh_packets++;

    if (tcp->fin)
        e->fin_packets++;

    if (tcp->rst)
        e->rst_packets++;

    if (tcp->sack_block_count > 0)
        e->sack_packets++;

    if (tcp->has_timestamp)
        e->timestamp_packets++;

    if (tcp->syn && !tcp->ack) {
        if (tcp->has_mss) {
            e->has_mss = 1;
            e->maximum_segment_size =
                tcp->maximum_segment_size;
        }

        if (tcp->has_window_scale) {
            e->has_window_scale = 1;
            e->window_scale =
                tcp->window_scale;
        }

        if (tcp->sack_permitted)
            e->sack_permitted = 1;
    }
}

double get_packet_timestamp(const pcapng_t *pcapng,
                            const packet_t *packet)
{
    uint64_t raw =
        ((uint64_t)packet->timestamp_high << 32) |
        packet->timestamp_low;

    double ts = (double)raw;

    if (packet->interface_id < pcapng->interface_count) {
        const idb_t *idb =
            &pcapng->interfaces[packet->interface_id];

        uint8_t tsresol = 6;

        for (size_t i = 0;
             i < idb->options_count;
             i++) {

            const options_t *opt =
                &idb->options[i];

            if (opt->code != 9 ||
                opt->length < 1 ||
                !opt->value)
                continue;

            tsresol = opt->value[0];
            break;
        }

        if (tsresol & 0x80) {
            uint8_t exp = tsresol & 0x7F;
            ts = ldexp(ts, -(int)exp);
        } else {
            ts /= pow(10.0, tsresol);
        }
    } else {
        ts /= 1000000.0;
    }

    return ts;
}