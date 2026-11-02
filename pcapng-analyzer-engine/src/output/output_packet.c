#include <stdio.h>
#include "output_packet.h"

#include <stdio.h>
#include "output_packet.h"

void print_packet(const packet_t *pkt)
{
    if (!pkt) {
        printf("Packet: NULL\n");
        return;
    }

    printf("Packet information:\n");
    printf("  Block type: %u\n", pkt->block_type);
    printf("  Interface ID: %u\n", pkt->interface_id);
    printf("  Link type: %u\n", pkt->link_type);

    printf("  Timestamp high: %u\n", pkt->timestamp_high);
    printf("  Timestamp low: %u\n", pkt->timestamp_low);

    printf("  Captured length: %u bytes\n", pkt->captured_packet_length);
    printf("  Original length: %u bytes\n", pkt->original_packet_length);

    printf("  Options count: %zu\n", pkt->options_count);

    printf("  Packet data pointer: %p\n", (void*)pkt->packet_data);

    printf("\n");
}
