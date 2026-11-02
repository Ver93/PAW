#include "idb_parser.h"

int parse_idb(FILE *f, idb_t *idb){
    DEBUG_PRINT("\nIDB BLOCK START\n");

    if (fread(&idb->block_type, sizeof(idb->block_type), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&idb->block_length, sizeof(idb->block_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&idb->link_type, sizeof(idb->link_type), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&idb->reserved, sizeof(idb->reserved), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&idb->snap_length, sizeof(idb->snap_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (file_endianness != get_system_endianness()) {
        idb->block_type = swap32(idb->block_type);
        idb->block_length = swap32(idb->block_length);
        idb->link_type = swap16(idb->link_type);
        idb->reserved = swap16(idb->reserved);
        idb->snap_length = swap32(idb->snap_length);
    }

    DEBUG_PRINT("IDB block_type:                0x%08X\n", idb->block_type);
    DEBUG_PRINT("IDB block_length:              %u\n", idb->block_length);
    DEBUG_PRINT("IDB link_type:                 %u\n", idb->link_type);
    DEBUG_PRINT("IDB snap_length:               %u\n", idb->snap_length);

    size_t header_size =
        sizeof(idb->block_type) +
        sizeof(idb->block_length) +
        sizeof(idb->link_type) +
        sizeof(idb->reserved) +
        sizeof(idb->snap_length);

    if (idb->block_length < header_size + 4)
        return PARSE_INVALID;

    size_t options_size =
        idb->block_length -
        header_size -
        4;

    if (options_size > 0) {
        DEBUG_PRINT("IDB options_size:          %zu bytes\n", options_size);

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

            DEBUG_PRINT("IDB option             code=%u length=%u\n",
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

            idb->options_count++;

            options_t *tmp =
                realloc(
                    idb->options,
                    idb->options_count *
                    sizeof(options_t)
                );

            if (tmp == NULL) {
                free(opt.value);
                idb->options_count--;
                return PARSE_OOM;
            }

            idb->options = tmp;
            idb->options[idb->options_count - 1] = opt;

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

    if (fread(&idb->block_footer, sizeof(idb->block_footer), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (file_endianness != get_system_endianness())
        idb->block_footer = swap32(idb->block_footer);

    if (idb->block_footer != idb->block_length)
        return PARSE_INVALID;

    DEBUG_PRINT("IDB block_footer:              0x%08X\n", idb->block_footer);
    DEBUG_PRINT("IDB END\n");

    return PARSE_OK;
}