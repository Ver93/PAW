#include <stdio.h>
#include <stdlib.h>

#include "tcp_timestamp_analysis.h"

static void update_tcp_timestamp_rtt_statistics(
    tcp_direction_analysis_t *direction,
    double rtt) {

    // Släng orimliga värden (t.ex. > 5 sekunder)
    if (rtt < 0.0 || rtt > 5.0)
        return;

    if (direction->tcp_timestamp_rtt_sample_count == 0) {

        direction->tcp_timestamp_rtt_min = rtt;
        direction->tcp_timestamp_rtt_max = rtt;

    } else {

        if (rtt < direction->tcp_timestamp_rtt_min)
            direction->tcp_timestamp_rtt_min = rtt;

        if (rtt > direction->tcp_timestamp_rtt_max)
            direction->tcp_timestamp_rtt_max = rtt;
    }

    direction->tcp_timestamp_rtt_sum += rtt;
    direction->tcp_timestamp_rtt_sample_count++;
}


void analyze_tcp_timestamp(
    tcp_direction_analysis_t *source_direction,
    tcp_direction_analysis_t *echoed_direction,
    const tcp_t *tcp,
    double timestamp) {

    if (!tcp->has_timestamp)
        return;

    /*
     * TSecr acknowledges a TSval sent by the opposite
     * direction.
     */
    if (tcp->timestamp_echo_reply != 0) {

        for (size_t i = 0;
             i < echoed_direction->timestamp_sample_count;
             i++) {

            tcp_timestamp_sample_t *sample =
                &echoed_direction->timestamp_samples[i];

            if (sample->matched)
                continue;

            if (sample->timestamp_value !=
                tcp->timestamp_echo_reply)
                continue;

            double rtt =
                timestamp - sample->timestamp_time;

            printf(
                "TCP TS RTT: TSval=%u TSecr=%u delta=%.6f\n",
                sample->timestamp_value,
                tcp->timestamp_echo_reply,
                rtt
            );

            if (rtt >= 0.0) {

                update_tcp_timestamp_rtt_statistics(
                    echoed_direction,
                    rtt
                );

                sample->matched = 1;
            }

            break;
        }
    }

    /*
     * TSval belongs to the current direction.
     */
    if (source_direction->timestamp_sample_count >=
        source_direction->timestamp_sample_capacity) {

        size_t new_capacity =
            source_direction->timestamp_sample_capacity == 0 ?
            16 :
            source_direction->timestamp_sample_capacity * 2;

        tcp_timestamp_sample_t *tmp =
            realloc(
                source_direction->timestamp_samples,
                new_capacity *
                sizeof(tcp_timestamp_sample_t)
            );

        if (!tmp)
            return;

        source_direction->timestamp_samples = tmp;
        source_direction->timestamp_sample_capacity =
            new_capacity;
    }

    tcp_timestamp_sample_t *sample =
        &source_direction->timestamp_samples[
            source_direction->timestamp_sample_count++
        ];

    sample->timestamp_value =
        tcp->timestamp_value;

    sample->timestamp_time =
        timestamp;

    sample->matched = 0;
}

void print_tcp_timestamp_rtt_analysis(
    const tcp_direction_analysis_t *direction) {

    printf("TCP TS RTT samples:   %zu\n",
           direction->tcp_timestamp_rtt_sample_count);

    if (direction->tcp_timestamp_rtt_sample_count > 0) {

        printf("TCP TS RTT min:       %.3f ms\n",
               direction->tcp_timestamp_rtt_min *
               1000.0);

        printf("TCP TS RTT max:       %.3f ms\n",
               direction->tcp_timestamp_rtt_max *
               1000.0);

        printf("TCP TS RTT average:   %.3f ms\n",
               (direction->tcp_timestamp_rtt_sum /
                direction->tcp_timestamp_rtt_sample_count) *
               1000.0);
    }
}