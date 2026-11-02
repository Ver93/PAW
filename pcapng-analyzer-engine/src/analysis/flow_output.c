#include <ctype.h>
#include <stdio.h>

#include "flow_output.h"

static void print_ip(const uint8_t ip[4])
{
    printf(
        "%u.%u.%u.%u",
        ip[0],
        ip[1],
        ip[2],
        ip[3]
    );
}

static void print_json_string(
    const uint8_t *data,
    size_t length
) {
    putchar('"');

    for (size_t i = 0; i < length; i++) {

        unsigned char c = data[i];

        switch (c) {

        case '\\':
            printf("\\\\");
            break;

        case '"':
            printf("\\\"");
            break;

        case '\b':
            printf("\\b");
            break;

        case '\f':
            printf("\\f");
            break;

        case '\n':
            printf("\\n");
            break;

        case '\r':
            printf("\\r");
            break;

        case '\t':
            printf("\\t");
            break;

        default:
            if (c >= 32 && c <= 126) {
                putchar(c);
            } else {
                printf("\\u%04x", c);
            }
            break;
        }
    }

    putchar('"');
}

static void print_payload_hex(
    const uint8_t *data,
    size_t length
) {
    putchar('"');

    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }

    putchar('"');
}

void print_flows_json(
    const flow_table_t *table
) {
    if (!table) {
        printf("{\"flows\":[]}\n");
        return;
    }

    printf("{\"flows\":[");

    for (size_t i = 0; i < table->count; i++) {

        const network_flow_t *flow =
            &table->flows[i];

        if (i > 0)
            printf(",");

        printf(
            "{"
            "\"id\":%zu,"
            "\"src\":\"",
            i
        );

        print_ip(flow->a.ip);

        printf(
            "\","
            "\"srcPort\":%u,"
            "\"dst\":\"",
            flow->a.port
        );

        print_ip(flow->b.ip);

        printf(
            "\","
            "\"dstPort\":%u,"
            "\"protocol\":\"%s\","
            "\"count\":%zu,"
            "\"packetsAToB\":%zu,"
            "\"packetsBToA\":%zu,"
            "\"packets\":[",
            flow->b.port,
            flow_protocol_name(flow->protocol),
            flow->packets,
            flow->packets_a_to_b,
            flow->packets_b_to_a
        );

        for (
            size_t j = 0;
            j < flow->packet_count;
            j++
        ) {

            const flow_packet_t *packet =
                &flow->packet_data[j];

            if (j > 0)
                printf(",");

            printf(
                "{"
                "\"packet\":%zu,"
                "\"direction\":\"%s\","
                "\"sequence\":%u,"
                "\"payloadLength\":%zu,"
                "\"reassembled\":%s,"
                "\"payloadHex\":",
                packet->packet_index,

                packet->direction == 0
                    ? "A_TO_B"
                    : "B_TO_A",

                packet->sequence,

                packet->payload_length,

                packet->reassembled
                    ? "true"
                    : "false"
            );

            if (
                packet->payload &&
                packet->payload_length > 0
            ) {
                print_payload_hex(
                    packet->payload,
                    packet->payload_length
                );
            } else {
                printf("\"\"");
            }

            printf(
                ",\"payloadText\":"
            );

            if (
                packet->payload &&
                packet->payload_length > 0
            ) {
                print_json_string(
                    packet->payload,
                    packet->payload_length
                );
            } else {
                printf("\"\"");
            }

            printf("}");
        }

        printf("]}");
    }

    printf("]}\n");
}