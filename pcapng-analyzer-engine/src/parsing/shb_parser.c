#include "shb_parser.h"

int parse_shb(FILE *f, shb_t *shb){
    
    DEBUG_PRINT("\nSHB BLOCK START\n");

    if (fread(&shb->block_type, sizeof(shb->block_type), 1, f) != 1)                return PARSE_TRUNCATED;
    if (fread(&shb->block_length, sizeof(shb->block_length), 1, f) != 1)            return PARSE_TRUNCATED;
    if (fread(&shb->byte_order_magic, sizeof(shb->byte_order_magic), 1, f) != 1)    return PARSE_TRUNCATED;
    if (fread(&shb->major_version, sizeof(shb->major_version), 1, f) != 1)          return PARSE_TRUNCATED;
    if (fread(&shb->minor_version, sizeof(shb->minor_version), 1, f) != 1)          return PARSE_TRUNCATED;
    if (fread(&shb->section_length, sizeof(shb->section_length), 1, f) != 1)        return PARSE_TRUNCATED;

    if (shb->byte_order_magic == 0x1A2B3C4D) {
        file_endianness = IS_LITTLE_ENDIAN;
    } else if (shb->byte_order_magic == 0x4D3C2B1A) {
        file_endianness = IS_BIG_ENDIAN;
    } else {
        return PARSE_INVALID;
    }

    DEBUG_PRINT("SHB block_type:                0x%08X\n", shb->block_type);
    DEBUG_PRINT("SHB block_length:              %u\n", shb->block_length);
    DEBUG_PRINT("SHB byte_order_magic:          0x%08X\n", shb->byte_order_magic);
    DEBUG_PRINT("File endianness:               %s\n", file_endianness == IS_LITTLE_ENDIAN ? "Little endian" : "Big endian");
    DEBUG_PRINT("SHB version:                   %u.%u\n", shb->major_version, shb->minor_version);
    DEBUG_PRINT("SHB section_length:            %llu\n", (unsigned long long)shb->section_length);

    if (file_endianness != get_system_endianness()) {
        shb->block_type     = swap32(shb->block_type);
        shb->block_length   = swap32(shb->block_length);
        shb->major_version  = swap16(shb->major_version);
        shb->minor_version  = swap16(shb->minor_version);
        shb->section_length = swap64(shb->section_length);
    }
    
    size_t header_size = sizeof(shb->block_type) + sizeof(shb->block_length) + sizeof(shb->byte_order_magic) + sizeof(shb->major_version) + sizeof(shb->minor_version) + sizeof(shb->section_length);

    if (shb->block_length < header_size + PCAPNG_ALIGNMENT)
        return PARSE_INVALID;

    size_t options_size = shb->block_length - header_size - PCAPNG_ALIGNMENT;

    if (options_size > 0) {
        DEBUG_PRINT("SHB options_size:          %zu bytes\n", options_size);

        size_t options_read = 0;

        while (options_read < options_size) {
            options_t opt = {0};

            if (fread(&opt.code, sizeof(opt.code), 1, f) != 1) return PARSE_TRUNCATED;
            if (fread(&opt.length, sizeof(opt.length), 1, f) != 1) return PARSE_TRUNCATED;

            options_read += PCAPNG_ALIGNMENT;

            if (file_endianness != get_system_endianness()) {
                opt.code = swap16(opt.code);
                opt.length = swap16(opt.length);
            }

            if (opt.code == PCAPNG_OPTION_END_OF_OPTIONS && opt.length == PCAPNG_OPTION_END_OF_OPTIONS)
                break;

            DEBUG_PRINT("SHB option             code=%u length=%u\n",
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
            shb->options_count++;

            options_t *tmp = realloc(shb->options, shb->options_count * sizeof(options_t));

            if (tmp == NULL) {
                free(opt.value);
                shb->options_count--;
                return PARSE_OOM;
            }

            shb->options = tmp;
            shb->options[shb->options_count - 1] = opt;

            size_t padding = (PCAPNG_ALIGNMENT - (opt.length % PCAPNG_ALIGNMENT)) % PCAPNG_ALIGNMENT;

            if (padding > 0) {
                if (padding > options_size - options_read)
                    return PARSE_INVALID;

                if (fseek(f, padding, SEEK_CUR) != 0)
                    return PARSE_IO_ERROR;

                options_read += padding;
            }
        }
    }

    if (fread(&shb->block_footer, sizeof(shb->block_footer), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (file_endianness != get_system_endianness())
        shb->block_footer = swap32(shb->block_footer);

    if (shb->block_footer != shb->block_length)
        return PARSE_INVALID;

    DEBUG_PRINT("SHB block_footer:              0x%08X\n", shb->block_footer);
    DEBUG_PRINT("SHB END\n");

    return PARSE_OK;
}