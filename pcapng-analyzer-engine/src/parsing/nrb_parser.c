#include "nrb_parser.h"

int parse_nrb(FILE *f, nrb_t *nrb){
    DEBUG_PRINT("\nNRB BLOCK START\n");

    if (fread(&nrb->block_type, sizeof(nrb->block_type), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (fread(&nrb->block_length, sizeof(nrb->block_length), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (file_endianness != get_system_endianness()) {
        nrb->block_type = swap32(nrb->block_type);
        nrb->block_length = swap32(nrb->block_length);
    }

    DEBUG_PRINT("NRB block_type:                0x%08X\n", nrb->block_type);
    DEBUG_PRINT("NRB block_length:              %u\n", nrb->block_length);

    if (nrb->block_length < 12)
        return PARSE_INVALID;

    size_t data_size =
        nrb->block_length - 12;

    size_t data_read = 0;

    while (data_read < data_size) {
        nrb_record_t record = {0};

        if (data_size - data_read < 4)
            return PARSE_INVALID;

        if (fread(&record.record_type, sizeof(record.record_type), 1, f) != 1)
            return PARSE_TRUNCATED;

        if (fread(&record.record_value_length, sizeof(record.record_value_length), 1, f) != 1)
            return PARSE_TRUNCATED;

        data_read += 4;

        if (file_endianness != get_system_endianness()) {
            record.record_type = swap16(record.record_type);
            record.record_value_length = swap16(record.record_value_length);
        }

        if (record.record_type == 0 && record.record_value_length == 0) {
            DEBUG_PRINT("NRB end of records\n");
            break;
        }

        DEBUG_PRINT("NRB record             type=%u length=%u\n",
                    record.record_type, record.record_value_length);

        if (record.record_value_length > data_size - data_read)
            return PARSE_INVALID;

        if (record.record_value_length > 0) {
            record.record_value = malloc(record.record_value_length);

            if (record.record_value == NULL)
                return PARSE_OOM;

            if (fread(record.record_value, record.record_value_length, 1, f) != 1) {
                free(record.record_value);
                return PARSE_TRUNCATED;
            }

            data_read += record.record_value_length;

            size_t padding =
                (4 - (record.record_value_length % 4)) % 4;

            if (padding > 0) {
                if (padding > data_size - data_read) {
                    free(record.record_value);
                    return PARSE_INVALID;
                }

                if (fseek(f, padding, SEEK_CUR) != 0) {
                    free(record.record_value);
                    return PARSE_IO_ERROR;
                }

                data_read += padding;
            }
        }

        nrb_record_t *tmp =
            realloc(
                nrb->records,
                (nrb->record_count + 1) *
                sizeof(nrb_record_t)
            );

        if (tmp == NULL) {
            free(record.record_value);
            return PARSE_OOM;
        }

        nrb->records = tmp;
        nrb->records[nrb->record_count++] = record;
    }

    if (fread(&nrb->block_footer, sizeof(nrb->block_footer), 1, f) != 1)
        return PARSE_TRUNCATED;

    if (file_endianness != get_system_endianness())
        nrb->block_footer = swap32(nrb->block_footer);

    if (nrb->block_footer != nrb->block_length)
        return PARSE_INVALID;

    DEBUG_PRINT("NRB block_footer:              0x%08X\n", nrb->block_footer);
    DEBUG_PRINT("NRB END\n");

    return PARSE_OK;
}