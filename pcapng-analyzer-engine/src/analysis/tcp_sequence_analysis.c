#include <stdlib.h>
#include <stdint.h>

#include "tcp_sequence_analysis.h"
#include "tcp_rtt_analysis.h"

static int sequence_before(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) < 0;
}

static int sequence_after(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) > 0;
}

// static int sequence_before_or_equal(uint32_t a, uint32_t b) {
//     return a == b || sequence_before(a, b);
// }

static uint32_t sequence_end(const tcp_t *tcp) {
    uint32_t end =
        tcp->sequence_number +
        (uint32_t)tcp->payload_length;

    if (tcp->syn)
        end++;

    if (tcp->fin)
        end++;

    return end;
}

static int sequence_range_overlaps(
    uint32_t start_a,
    uint32_t end_a,
    uint32_t start_b,
    uint32_t end_b) {

    if (start_a == end_a || start_b == end_b)
        return 0;

    return sequence_before(start_a, end_b) &&
           sequence_before(start_b, end_a);
}

static int add_sequence_range(
    tcp_direction_analysis_t *direction,
    uint32_t start,
    uint32_t end) {

    if (direction->range_count >= direction->range_capacity) {
        size_t new_capacity =
            direction->range_capacity == 0 ?
            16 :
            direction->range_capacity * 2;

        tcp_sequence_range_t *tmp =
            realloc(
                direction->ranges,
                new_capacity * sizeof(tcp_sequence_range_t)
            );

        if (!tmp)
            return 0;

        direction->ranges = tmp;
        direction->range_capacity = new_capacity;
    }

    direction->ranges[direction->range_count].sequence_start =
        start;

    direction->ranges[direction->range_count].sequence_end =
        end;

    direction->range_count++;

    return 1;
}

void analyze_tcp_sequence(
    tcp_direction_analysis_t *direction,
    const tcp_t *tcp,
    double timestamp) {

    uint32_t start =
        tcp->sequence_number;

    uint32_t end =
        sequence_end(tcp);

    if (start == end)
        return;

    int overlaps = 0;

    for (size_t i = 0;
         i < direction->range_count;
         i++) {

        tcp_sequence_range_t *range =
            &direction->ranges[i];

        if (sequence_range_overlaps(
                start,
                end,
                range->sequence_start,
                range->sequence_end)) {

            overlaps = 1;
            break;
        }
    }

    if (overlaps) {

        direction->retransmissions++;

        /*
         * Karn's algorithm:
         * a retransmitted segment cannot be used
         * for RTT measurement.
         */
        if (direction->rtt_probe_initialized &&
            sequence_range_overlaps(
                start,
                end,
                direction->rtt_probe.sequence_start,
                direction->rtt_probe.sequence_end)) {

            direction->rtt_probe_initialized = 0;
        }

    } else if (direction->sequence_initialized) {

        if (sequence_after(
                start,
                direction->next_sequence)) {

            direction->out_of_order++;
            direction->sequence_gaps++;
        }
    }

    if (!direction->sequence_initialized) {

        direction->next_sequence = end;
        direction->sequence_initialized = 1;

    } else if (sequence_after(
                   end,
                   direction->next_sequence)) {

        direction->next_sequence = end;
    }

    if (!direction->highest_sequence_initialized ||
        sequence_after(
            end,
            direction->highest_sequence)) {

        direction->highest_sequence = end;
        direction->highest_sequence_initialized = 1;
    }

    if (!add_sequence_range(
            direction,
            start,
            end)) {

        return;
    }

    /*
     * Use the latest new segment as the RTT probe.
     *
     * Do not use retransmitted segments.
     */
    if (!overlaps) {

        direction->rtt_probe.sequence_start =
            start;

        direction->rtt_probe.sequence_end =
            end;

        direction->rtt_probe.timestamp =
            timestamp;

        direction->rtt_probe.retransmitted = 0;
        direction->rtt_probe.acknowledged = 0;

        direction->rtt_probe_initialized = 1;
    }
}