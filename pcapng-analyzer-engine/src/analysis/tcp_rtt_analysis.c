#include <stdio.h>
#include <stdlib.h>

#include "tcp_rtt_analysis.h"

static int compare_double(
    const void *a,
    const void *b) {

    double da = *(const double *)a;
    double db = *(const double *)b;

    if (da < db)
        return -1;

    if (da > db)
        return 1;

    return 0;
}

static double percentile(
    double *samples,
    size_t count,
    double percentile_value) {

    if (count == 0)
        return 0.0;

    qsort(
        samples,
        count,
        sizeof(double),
        compare_double
    );

    double position =
        percentile_value *
        (double)(count - 1);

    size_t lower =
        (size_t)position;

    size_t upper =
        lower + 1;

    if (upper >= count)
        return samples[lower];

    double fraction =
        position - (double)lower;

    return samples[lower] +
           (samples[upper] - samples[lower]) *
           fraction;
}

static void calculate_rtt_distribution(
    tcp_direction_analysis_t *direction) {

    if (direction->rtt_sample_count == 0)
        return;

    double *samples =
        malloc(
            direction->rtt_sample_count *
            sizeof(double)
        );

    if (!samples)
        return;

    for (size_t i = 0;
         i < direction->rtt_sample_count;
         i++) {

        samples[i] =
            direction->rtt_samples[i];
    }

    direction->rtt_median =
        percentile(
            samples,
            direction->rtt_sample_count,
            0.50
        );

    direction->rtt_p95 =
        percentile(
            samples,
            direction->rtt_sample_count,
            0.95
        );

    direction->rtt_p99 =
        percentile(
            samples,
            direction->rtt_sample_count,
            0.99
        );

    free(samples);
}

void update_tcp_rtt_statistics(
    tcp_direction_analysis_t *direction,
    double rtt) {

    // Släng orimliga RTT-värden: t.ex. > 5 sekunder
    if (rtt < 0.0 || rtt > 5.0)
        return;

    if (direction->rtt_sample_count == 0) {
        direction->rtt_min = rtt;
        direction->rtt_max = rtt;
    } else {
        if (rtt < direction->rtt_min)
            direction->rtt_min = rtt;
        if (rtt > direction->rtt_max)
            direction->rtt_max = rtt;
    }

    direction->rtt_sum += rtt;

    if (direction->rtt_sample_count >= direction->rtt_sample_capacity) {
        size_t new_capacity =
            direction->rtt_sample_capacity == 0 ? 16 :
            direction->rtt_sample_capacity * 2;

        double *tmp = realloc(
            direction->rtt_samples,
            new_capacity * sizeof(double)
        );

        if (!tmp)
            return;

        direction->rtt_samples = tmp;
        direction->rtt_sample_capacity = new_capacity;
    }

    direction->rtt_samples[
        direction->rtt_sample_count++
    ] = rtt;

    calculate_rtt_distribution(direction);
}


void analyze_tcp_ack(
    tcp_direction_analysis_t *direction,
    const tcp_t *tcp,
    double timestamp) {

    if (!tcp->ack)
        return;

    uint32_t acknowledgment =
        tcp->acknowledgment_number;

    if (!direction->acknowledgment_initialized) {

        direction->last_acknowledgment =
            acknowledgment;

        direction->acknowledgment_initialized = 1;

    } else if (acknowledgment ==
               direction->last_acknowledgment) {

        if (direction->highest_sequence_initialized &&
            (int32_t)(
                acknowledgment -
                direction->highest_sequence
            ) < 0) {

            direction->duplicate_acks++;
        }

        return;

    } else if (
        (int32_t)(
            acknowledgment -
            direction->last_acknowledgment
        ) > 0) {

        direction->last_acknowledgment =
            acknowledgment;

    } else {

        return;
    }

    if (!direction->rtt_probe_initialized)
        return;

    tcp_rtt_segment_t *probe =
        &direction->rtt_probe;

    if (probe->acknowledged)
        return;

    if ((int32_t)(
            probe->sequence_end -
            acknowledgment
        ) > 0) {

        return;
    }

    double rtt =
        timestamp - probe->timestamp;

    if (rtt < 0.0)
        return;

    update_tcp_rtt_statistics(
        direction,
        rtt
    );

    probe->acknowledged = 1;
    direction->rtt_probe_initialized = 0;
}

void print_tcp_rtt_analysis(
    const tcp_direction_analysis_t *direction) {

    printf("ACK RTT samples:      %zu\n",
           direction->rtt_sample_count);

    if (direction->rtt_sample_count == 0)
        return;

    printf("ACK RTT min:          %.3f ms\n",
           direction->rtt_min * 1000.0);

    printf("ACK RTT max:          %.3f ms\n",
           direction->rtt_max * 1000.0);

    printf("ACK RTT average:      %.3f ms\n",
           (direction->rtt_sum /
            direction->rtt_sample_count) *
           1000.0);

    printf("ACK RTT median:       %.3f ms\n",
           direction->rtt_median * 1000.0);

    printf("ACK RTT P95:          %.3f ms\n",
           direction->rtt_p95 * 1000.0);

    printf("ACK RTT P99:          %.3f ms\n",
           direction->rtt_p99 * 1000.0);
}