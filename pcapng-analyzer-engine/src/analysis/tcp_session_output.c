#include <stdio.h>

#include "tcp_session_output.h"
#include "tcp_session_state.h"

static void print_ip(const uint8_t ip[4])
{
    printf("%u.%u.%u.%u",
           ip[0],
           ip[1],
           ip[2],
           ip[3]);
}

static void print_tcp_endpoint(
    const tcp_session_endpoint_t *e)
{
    print_ip(e->ip);
    printf(":%u", e->port);
}

static void print_tcp_direction(
    const tcp_direction_analysis_t *dir,
    const tcp_session_endpoint_t *src,
    const tcp_session_endpoint_t *dst)
{
    print_tcp_endpoint(src);
    printf(" -> ");
    print_tcp_endpoint(dst);
    printf("\n");

    printf("Packets:              %zu\n", src->packets);
    printf("Payload bytes:        %zu\n", src->payload_bytes);
    printf("Retransmissions:      %zu\n", dir->retransmissions);
    printf("Out-of-order:         %zu\n", dir->out_of_order);
    printf("Sequence gaps:        %zu\n", dir->sequence_gaps);
    printf("Duplicate ACK:        %zu\n", dir->duplicate_acks);

    if (dir->highest_sequence_initialized)
        printf("Highest sequence end: %u\n",
               dir->highest_sequence);

    printf("\n");

    print_tcp_rtt_analysis(dir);
    print_tcp_timestamp_rtt_analysis(dir);
}

void print_tcp_sessions(const packet_summary_t *summary)
{
    printf("\nTCP SESSIONS\n");
    printf("=============================\n");

    printf("Sessions:             %zu\n",
           summary->tcp_session_count);

    for (size_t i = 0;
         i < summary->tcp_session_count;
         i++) {

        const tcp_session_t *s =
            &summary->tcp_sessions[i];

        printf("\nSession %zu\n", i + 1);

        printf("Endpoint A: ");
        print_tcp_endpoint(&s->endpoint_a);
        printf("\n");

        printf("Endpoint B: ");
        print_tcp_endpoint(&s->endpoint_b);
        printf("\n");

        printf("Client:               ");

        if (!s->client_known) {
            printf("unknown\n");
        } else {
            print_tcp_endpoint(
                s->client_is_a
                    ? &s->endpoint_a
                    : &s->endpoint_b);

            printf("\n");
        }

        printf("Packets:              %zu\n",
               s->packets);

        printf("Payload bytes:        %zu\n",
               s->payload_bytes);

        printf("A -> B packets:       %zu\n",
               s->packets_a_to_b);

        printf("B -> A packets:       %zu\n",
               s->packets_b_to_a);

        printf("A -> B payload:       %zu\n",
               s->payload_bytes_a_to_b);

        printf("B -> A payload:       %zu\n",
               s->payload_bytes_b_to_a);

        printf("SYN:                  %zu\n",
               s->syn_packets);

        printf("SYN-ACK:              %zu\n",
               s->syn_ack_packets);

        printf("ACK:                  %zu\n",
               s->ack_packets);

        printf("PSH:                  %zu\n",
               s->psh_packets);

        printf("FIN:                  %zu\n",
               s->fin_packets);

        printf("RST:                  %zu\n",
               s->rst_packets);

        printf("SACK:                 %zu\n",
               s->sack_packets);

        printf("Timestamp:            %zu\n",
               s->timestamp_packets);

        printf("State:                %s\n",
               tcp_state_name(s->state));

        printf("Handshake:            %s\n",
               tcp_state_handshake_observed(s->state)
                   ? "observed"
                   : "not observed");

        printf("Established:          %s\n",
               tcp_state_established(s->state)
                   ? "yes"
                   : "no");

        printf("Closed:               %s\n",
               tcp_state_closed(s->state)
                   ? "yes"
                   : "no");

        printf("FIN A seen:           %s\n",
               s->fin_a_seen ? "yes" : "no");

        printf("FIN B seen:           %s\n",
               s->fin_b_seen ? "yes" : "no");

        printf("FIN A acknowledged:   %s\n",
               s->fin_a_acknowledged ? "yes" : "no");

        printf("FIN B acknowledged:   %s\n",
               s->fin_b_acknowledged ? "yes" : "no");

        printf("\nTCP SEQUENCE ANALYSIS A -> B\n");

        print_tcp_direction(
            &s->direction_a_to_b,
            &s->endpoint_a,
            &s->endpoint_b);

        printf("\nTCP SEQUENCE ANALYSIS B -> A\n");

        print_tcp_direction(
            &s->direction_b_to_a,
            &s->endpoint_b,
            &s->endpoint_a);
    }
}