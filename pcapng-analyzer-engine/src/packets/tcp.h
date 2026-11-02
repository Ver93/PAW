#ifndef TCP_H
#define TCP_H

#include <stddef.h>
#include <stdint.h>

#define TCP_MAX_SACK_BLOCKS 4

typedef struct {
    uint32_t left_edge;
    uint32_t right_edge;
} tcp_sack_block_t;

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;

    uint32_t sequence_number;
    uint32_t acknowledgment_number;

    uint8_t data_offset;

    uint8_t ns;
    uint8_t cwr;
    uint8_t ece;
    uint8_t urg;
    uint8_t ack;
    uint8_t psh;
    uint8_t rst;
    uint8_t syn;
    uint8_t fin;

    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;

    int has_mss;
    uint16_t maximum_segment_size;

    int has_window_scale;
    uint8_t window_scale;

    int sack_permitted;

    size_t sack_block_count;
    tcp_sack_block_t sack_blocks[TCP_MAX_SACK_BLOCKS];

    int has_timestamp;
    uint32_t timestamp_value;
    uint32_t timestamp_echo_reply;

    size_t options_offset;
    size_t options_length;

    size_t payload_offset;
    size_t payload_length;
} tcp_t;

#endif