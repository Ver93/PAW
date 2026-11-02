#ifndef PCAPNG_BLOCKS_H
#define PCAPNG_BLOCKS_H

#include <stdint.h>

typedef enum {
    SHB = 0x0A0D0D0A,
    IDB = 0x00000001,
    PB  = 0x00000002,
    SPB = 0x00000003,
    NRB = 0x00000004,
    ISB = 0x00000005,
    EPB = 0x00000006,
    DSB = 0x0000000A,
    CUSTOM = 0x00000000,
} blocks_t;

typedef struct {
    uint16_t code;
    uint16_t length;
    uint8_t *value;
} options_t;

typedef struct {
    uint16_t record_type;
    uint16_t record_value_length;
    uint8_t *record_value;
} nrb_record_t;

typedef struct {
    uint32_t block_type;

    uint32_t interface_id;
    
    uint16_t link_type;

    uint32_t timestamp_high;
    uint32_t timestamp_low;

    uint32_t captured_packet_length;
    uint32_t original_packet_length;

    uint8_t *packet_data;

    options_t *options;
    size_t options_count;

} packet_t;

typedef struct {
    uint32_t block_type;
    uint32_t block_length;
    uint32_t byte_order_magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint64_t section_length;

    options_t *options;
    size_t options_count;

    uint32_t block_footer;
} shb_t;

typedef struct {
    uint32_t block_type;
    uint32_t block_length;

    uint16_t link_type;
    uint16_t reserved;
    uint32_t snap_length;

    options_t *options;
    size_t options_count;

    uint32_t block_footer;
} idb_t;

typedef struct {
    uint32_t block_type;
    uint32_t block_length;

    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;

    options_t *options;
    size_t options_count;

    uint32_t block_footer;
} isb_t;

typedef struct {
    uint32_t block_type;
    uint32_t block_length;

    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;

    uint32_t captured_packet_length;
    uint32_t original_packet_length;

    uint8_t *packet_data;

    options_t *options;
    size_t options_count;

    uint32_t block_footer;
} epb_t;

typedef struct {
    uint32_t block_type;
    uint32_t block_length;

    nrb_record_t *records;
    size_t record_count;

    uint32_t block_footer;
} nrb_t;

typedef struct {
    uint32_t block_type;
    uint32_t block_length;

    uint16_t interface_id;
    uint16_t drops_count;

    uint32_t timestamp_high;
    uint32_t timestamp_low;

    uint32_t captured_packet_length;
    uint32_t original_packet_length;

    uint8_t *packet_data;

    options_t *options;
    size_t options_count;

    uint32_t block_footer;
} pb_t;

typedef struct {
    uint32_t block_type;
    uint32_t block_length;

    uint32_t original_packet_length;
    uint32_t captured_packet_length;

    uint8_t *packet_data;

    uint32_t block_footer;
} spb_t;

#endif