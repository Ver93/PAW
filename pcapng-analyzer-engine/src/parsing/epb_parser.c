#include "epb_parser.h"

int parse_epb(FILE *f, epb_t *epb){
    DEBUG_PRINT("\nEPB BLOCK START\n");

    if (fread(&epb->block_type, sizeof(epb->block_type), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&epb->block_length, sizeof(epb->block_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&epb->interface_id, sizeof(epb->interface_id), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&epb->timestamp_high, sizeof(epb->timestamp_high), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&epb->timestamp_low, sizeof(epb->timestamp_low), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&epb->captured_packet_length, sizeof(epb->captured_packet_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&epb->original_packet_length, sizeof(epb->original_packet_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (file_endianness != get_system_endianness()) {
        epb->block_type = swap32(epb->block_type);
        epb->block_length = swap32(epb->block_length);
        epb->interface_id = swap32(epb->interface_id);
        epb->timestamp_high = swap32(epb->timestamp_high);
        epb->timestamp_low = swap32(epb->timestamp_low);
        epb->captured_packet_length = swap32(epb->captured_packet_length);
        epb->original_packet_length = swap32(epb->original_packet_length);
    }

    DEBUG_PRINT("EPB block_type:                %u\n", epb->block_type);
    DEBUG_PRINT("EPB block_length:              %u\n", epb->block_length);
    DEBUG_PRINT("EPB interface_id:              %u\n", epb->interface_id);
    DEBUG_PRINT("EPB captured_packet_length:    %u\n", epb->captured_packet_length);
    DEBUG_PRINT("EPB original_packet_length:    %u\n", epb->original_packet_length);

    size_t header_size =
        sizeof(epb->block_type) +
        sizeof(epb->block_length) +
        sizeof(epb->interface_id) +
        sizeof(epb->timestamp_high) +
        sizeof(epb->timestamp_low) +
        sizeof(epb->captured_packet_length) +
        sizeof(epb->original_packet_length);

    if (epb->block_length < header_size + 4)
        return PARSE_INVALID;

    size_t packet_padding =
        (4 - (epb->captured_packet_length % 4)) % 4;

    size_t minimum_length =
        header_size +
        epb->captured_packet_length +
        packet_padding +
        4;

    if (epb->block_length < minimum_length)
        return PARSE_INVALID;

    epb->packet_data = malloc(epb->captured_packet_length);

    if (epb->packet_data == NULL)
        return PARSE_OOM;

    if (fread(epb->packet_data, epb->captured_packet_length, 1, f) != 1) {
        free(epb->packet_data);
        epb->packet_data = NULL;
        return PARSE_TRUNCATED;
    }

    if (packet_padding > 0) {
        if (fseek(f, packet_padding, SEEK_CUR) != 0) {
            free(epb->packet_data);
            epb->packet_data = NULL;
            return PARSE_IO_ERROR;
        }
    }

    size_t options_size =
        epb->block_length -
        header_size -
        epb->captured_packet_length -
        packet_padding -
        4;

    if (options_size > 0) {
        DEBUG_PRINT("EPB options_size:          %zu bytes\n", options_size);

        size_t options_read = 0;

        while (options_read < options_size) {
            options_t opt;
            memset(&opt, 0, sizeof(opt));

            if (fread(&opt.code, sizeof(opt.code), 1, f) != 1) {
                free(epb->packet_data);
                epb->packet_data = NULL;
                return PARSE_TRUNCATED;
            }

            if (fread(&opt.length, sizeof(opt.length), 1, f) != 1) {
                free(epb->packet_data);
                epb->packet_data = NULL;
                return PARSE_TRUNCATED;
            }

            options_read += 4;

            if (file_endianness != get_system_endianness()) {
                opt.code = swap16(opt.code);
                opt.length = swap16(opt.length);
            }

            if (opt.code == 0 && opt.length == 0)
                break;

            DEBUG_PRINT("EPB option             code=%u length=%u\n",
                        opt.code, opt.length);

            if (opt.length > options_size - options_read) {
                free(epb->packet_data);
                epb->packet_data = NULL;
                return PARSE_INVALID;
            }

            opt.value = malloc(opt.length);

            if (opt.value == NULL) {
                free(epb->packet_data);
                epb->packet_data = NULL;
                return PARSE_OOM;
            }

            if (fread(opt.value, opt.length, 1, f) != 1) {
                free(opt.value);
                free(epb->packet_data);
                epb->packet_data = NULL;
                return PARSE_TRUNCATED;
            }

            options_read += opt.length;

            epb->options_count++;

            options_t *tmp =
                realloc(
                    epb->options,
                    epb->options_count *
                    sizeof(options_t)
                );

            if (tmp == NULL) {
                free(opt.value);
                free(epb->packet_data);
                epb->packet_data = NULL;
                epb->options_count--;
                return PARSE_OOM;
            }

            epb->options = tmp;
            epb->options[epb->options_count - 1] = opt;

            size_t padding =
                (4 - (opt.length % 4)) % 4;

            if (padding > 0) {
                if (padding > options_size - options_read) {
                    free(epb->packet_data);
                    epb->packet_data = NULL;
                    return PARSE_INVALID;
                }

                if (fseek(f, padding, SEEK_CUR) != 0) {
                    free(epb->packet_data);
                    epb->packet_data = NULL;
                    return PARSE_IO_ERROR;
                }

                options_read += padding;
            }
        }
    }

    if (fread(&epb->block_footer, sizeof(epb->block_footer), 1, f) != 1) {
        free(epb->packet_data);
        epb->packet_data = NULL;
        return PARSE_TRUNCATED;
    }

    if (file_endianness != get_system_endianness())
        epb->block_footer = swap32(epb->block_footer);

    if (epb->block_footer != epb->block_length) {
        free(epb->packet_data);
        epb->packet_data = NULL;
        return PARSE_INVALID;
    }

    DEBUG_PRINT("EPB block_footer:              %u\n", epb->block_footer);
    DEBUG_PRINT("EPB END\n");

    return PARSE_OK;
}