#include "isb_parser.h"

int parse_isb(FILE *f, isb_t *isb){
    DEBUG_PRINT("\nISB BLOCK START\n");

    if (fread(&isb->block_type, sizeof(isb->block_type), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&isb->block_length, sizeof(isb->block_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&isb->interface_id, sizeof(isb->interface_id), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&isb->timestamp_high, sizeof(isb->timestamp_high), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&isb->timestamp_low, sizeof(isb->timestamp_low), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (file_endianness != get_system_endianness()) {
        isb->block_type = swap32(isb->block_type);
        isb->block_length = swap32(isb->block_length);
        isb->interface_id = swap32(isb->interface_id);
        isb->timestamp_high = swap32(isb->timestamp_high);
        isb->timestamp_low = swap32(isb->timestamp_low);
    }

    DEBUG_PRINT("ISB block_type:                0x%08X\n", isb->block_type);
    DEBUG_PRINT("ISB block_length:              %u\n", isb->block_length);
    DEBUG_PRINT("ISB interface_id:              %u\n", isb->interface_id);
    DEBUG_PRINT("ISB timestamp_high:            %u\n", isb->timestamp_high);
    DEBUG_PRINT("ISB timestamp_low:             %u\n", isb->timestamp_low);

    size_t header_size =
        sizeof(isb->block_type) +
        sizeof(isb->block_length) +
        sizeof(isb->interface_id) +
        sizeof(isb->timestamp_high) +
        sizeof(isb->timestamp_low);

    if (isb->block_length < header_size + 4)
        return PARSE_INVALID;

    size_t options_size =
        isb->block_length -
        header_size -
        4;

    if (options_size > 0) {
        DEBUG_PRINT("ISB options_size:          %zu bytes\n", options_size);

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

            DEBUG_PRINT("ISB option             code=%u length=%u\n",
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

            isb->options_count++;

            options_t *tmp =
                realloc(
                    isb->options,
                    isb->options_count *
                    sizeof(options_t)
                );

            if (tmp == NULL) {
                free(opt.value);
                isb->options_count--;
                return PARSE_OOM;
            }

            isb->options = tmp;
            isb->options[isb->options_count - 1] = opt;

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

    if (fread(&isb->block_footer, sizeof(isb->block_footer), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (file_endianness != get_system_endianness())
        isb->block_footer = swap32(isb->block_footer);

    if (isb->block_footer != isb->block_length)
        return PARSE_INVALID;

    DEBUG_PRINT("ISB block_footer:              0x%08X\n", isb->block_footer);
    DEBUG_PRINT("ISB END\n");

    return PARSE_OK;
}