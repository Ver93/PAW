#include "endianness.h"

endianness_t file_endianness;

endianness_t get_system_endianness() {
    uint16_t num = 1;
    return (*(uint8_t *)&num == 1) ? IS_LITTLE_ENDIAN : IS_BIG_ENDIAN;
}

uint16_t swap16(uint16_t x) {
    return (x >> 8) | (x << 8);
}

uint32_t swap32(uint32_t x) {
    return __builtin_bswap32(x);
}

uint64_t swap64(uint64_t x) {
    return __builtin_bswap64(x);
}
uint16_t read_u16(const uint8_t *buf, endianness_t file_endianness) {
    uint16_t value = (buf[0] << 8) | buf[1];

    if (file_endianness != get_system_endianness())
        value = swap16(value);

    return value;
}

uint32_t read_u32(const uint8_t *buf, endianness_t file_endianness) {
    uint32_t value =
        ((uint32_t)buf[0] << 24) |
        ((uint32_t)buf[1] << 16) |
        ((uint32_t)buf[2] << 8)  |
        buf[3];

    if (file_endianness != get_system_endianness())
        value = swap32(value);

    return value;
}

uint64_t read_u64(const uint8_t *buf, endianness_t file_endianness) {
    uint64_t value =
        ((uint64_t)buf[0] << 56) |
        ((uint64_t)buf[1] << 48) |
        ((uint64_t)buf[2] << 40) |
        ((uint64_t)buf[3] << 32) |
        ((uint64_t)buf[4] << 24) |
        ((uint64_t)buf[5] << 16) |
        ((uint64_t)buf[6] << 8)  |
        buf[7];

    if (file_endianness != get_system_endianness())
        value = swap64(value);

    return value;
}
