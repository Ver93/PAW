#include "pb_parser.h"

int parse_pb(FILE *f, pb_t *pb){
    DEBUG_PRINT("\nPB BLOCK START\n");

    if (fread(&pb->block_type, sizeof(pb->block_type), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&pb->block_length, sizeof(pb->block_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&pb->interface_id, sizeof(pb->interface_id), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&pb->drops_count, sizeof(pb->drops_count), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&pb->timestamp_high, sizeof(pb->timestamp_high), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&pb->timestamp_low, sizeof(pb->timestamp_low), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&pb->captured_packet_length, sizeof(pb->captured_packet_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&pb->original_packet_length, sizeof(pb->original_packet_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (file_endianness != get_system_endianness()) {
        pb->block_type = swap32(pb->block_type);
        pb->block_length = swap32(pb->block_length);
        pb->interface_id = swap16(pb->interface_id);
        pb->drops_count = swap16(pb->drops_count);
        pb->timestamp_high = swap32(pb->timestamp_high);
        pb->timestamp_low = swap32(pb->timestamp_low);
        pb->captured_packet_length = swap32(pb->captured_packet_length);
        pb->original_packet_length = swap32(pb->original_packet_length);
    }

    DEBUG_PRINT("PB block_type:                0x%08X\n", pb->block_type);
    DEBUG_PRINT("PB block_length:              %u\n", pb->block_length);
    DEBUG_PRINT("PB interface_id:              %u\n", pb->interface_id);
    DEBUG_PRINT("PB drops_count:               %u\n", pb->drops_count);
    DEBUG_PRINT("PB captured_packet_length:    %u\n", pb->captured_packet_length);
    DEBUG_PRINT("PB original_packet_length:    %u\n", pb->original_packet_length);

    size_t header_size =
        sizeof(pb->block_type) +
        sizeof(pb->block_length) +
        sizeof(pb->interface_id) +
        sizeof(pb->drops_count) +
        sizeof(pb->timestamp_high) +
        sizeof(pb->timestamp_low) +
        sizeof(pb->captured_packet_length) +
        sizeof(pb->original_packet_length);

    if (pb->block_length < header_size + 4)
        return PARSE_INVALID;

    int packet_padding =
        (4 - (pb->captured_packet_length % 4)) % 4;

    size_t minimum_length =
        header_size +
        pb->captured_packet_length +
        packet_padding +
        4;

    if (pb->block_length < minimum_length)
        return PARSE_INVALID;

    pb->packet_data = malloc(pb->captured_packet_length);

    if (pb->packet_data == NULL)
        return PARSE_OOM;

    if (fread(pb->packet_data, pb->captured_packet_length, 1, f) != 1) {
        free(pb->packet_data);
        pb->packet_data = NULL;
        return PARSE_TRUNCATED;
    }

    if (packet_padding > 0) {
        if (fseek(f, packet_padding, SEEK_CUR) != 0) {
            free(pb->packet_data);
            pb->packet_data = NULL;
            return PARSE_IO_ERROR;
        }
    }

    size_t options_size =
        pb->block_length -
        header_size -
        pb->captured_packet_length -
        packet_padding -
        4;

    if (options_size > 0) {
        DEBUG_PRINT("PB options_size:          %zu bytes\n", options_size);

        size_t options_read = 0;

        while (options_read < options_size) {
            options_t opt;
            memset(&opt, 0, sizeof(opt));

            if (fread(&opt.code, sizeof(opt.code), 1, f) != 1)
                return PARSE_TRUNCATED;

            if (fread(&opt.length, sizeof(opt.length), 1, f) != 1)
                return PARSE_TRUNCATED;

            options_read += 4;

            if (file_endianness != get_system_endianness()) {
                opt.code = swap16(opt.code);
                opt.length = swap16(opt.length);
            }

            if (opt.code == 0 && opt.length == 0)
                break;

            DEBUG_PRINT("PB option             code=%u length=%u\n",
                        opt.code, opt.length);

            if (opt.length > options_size - options_read)
                return PARSE_INVALID;

            opt.value = malloc(opt.length);

            if (opt.value == NULL)
                return PARSE_OOM;

            if (fread(opt.value, opt.length, 1, f) != 1) {
                free(opt.value);
                return PARSE_TRUNCATED;
            }

            options_read += opt.length;

            pb->options_count++;

            options_t *tmp =
                realloc(
                    pb->options,
                    pb->options_count *
                    sizeof(options_t)
                );

            if (tmp == NULL) {
                free(opt.value);
                pb->options_count--;
                return PARSE_OOM;
            }

            pb->options = tmp;
            pb->options[pb->options_count - 1] = opt;

            size_t padding =
                (4 - (opt.length % 4)) % 4;

            if (padding > 0) {
                if (padding > options_size - options_read)
                    return PARSE_INVALID;

                if (fseek(f, padding, SEEK_CUR) != 0)
                    return PARSE_IO_ERROR;

                options_read += padding;
            }
        }
    }

    if (fread(&pb->block_footer, sizeof(pb->block_footer), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (file_endianness != get_system_endianness())
        pb->block_footer = swap32(pb->block_footer);

    if (pb->block_footer != pb->block_length)
        return PARSE_INVALID;

    DEBUG_PRINT("PB block_footer:              0x%08X\n", pb->block_footer);
    DEBUG_PRINT("PB END\n");

    return PARSE_OK;
}