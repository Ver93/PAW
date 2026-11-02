#include "spb_parser.h"

int parse_spb(FILE *f, spb_t *spb){
    DEBUG_PRINT("\nSPB BLOCK START\n");

    if (fread(&spb->block_type, sizeof(spb->block_type), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&spb->block_length, sizeof(spb->block_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&spb->original_packet_length, sizeof(spb->original_packet_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (file_endianness != get_system_endianness()) {
        spb->block_type = swap32(spb->block_type);
        spb->block_length = swap32(spb->block_length);
        spb->original_packet_length = swap32(spb->original_packet_length);
    }

    DEBUG_PRINT("SPB block_type:                0x%08X\n", spb->block_type);
    DEBUG_PRINT("SPB block_length:              %u\n", spb->block_length);
    DEBUG_PRINT("SPB original_packet_length:    %u\n", spb->original_packet_length);

    size_t header_size =
        sizeof(spb->block_type) +
        sizeof(spb->block_length) +
        sizeof(spb->original_packet_length);

    if (spb->block_length < header_size + 4)
        return PARSE_INVALID;

    size_t packet_data_size =
        spb->block_length -
        header_size -
        4;

    spb->captured_packet_length = packet_data_size;

    spb->packet_data = malloc(packet_data_size);

    if (spb->packet_data == NULL)
        return PARSE_OOM;

    if (fread(spb->packet_data, packet_data_size, 1, f) != 1) {
        free(spb->packet_data);
        spb->packet_data = NULL;
        return PARSE_TRUNCATED;
    }

    if (fread(&spb->block_footer, sizeof(spb->block_footer), 1, f) != 1) {
        free(spb->packet_data);
        spb->packet_data = NULL;
        return PARSE_TRUNCATED;
    }

    if (file_endianness != get_system_endianness())
        spb->block_footer = swap32(spb->block_footer);

    if (spb->block_footer != spb->block_length) {
        free(spb->packet_data);
        spb->packet_data = NULL;
        return PARSE_INVALID;
    }

    DEBUG_PRINT("SPB captured_packet_length:    %u\n",
                spb->captured_packet_length);

    DEBUG_PRINT("SPB block_footer:              0x%08X\n",
                spb->block_footer);

    DEBUG_PRINT("SPB END\n");

    return PARSE_OK;
}