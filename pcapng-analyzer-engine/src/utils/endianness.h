#ifndef ENDIANNESS_H
#define ENDIANNESS_H

#include <stdint.h>

typedef enum {
    IS_LITTLE_ENDIAN = 0,
    IS_BIG_ENDIAN    = 1
} endianness_t;

extern endianness_t file_endianness;

endianness_t get_system_endianness(void);

uint16_t swap16(uint16_t x);
uint32_t swap32(uint32_t x);
uint64_t swap64(uint64_t x);

uint16_t read_u16(const uint8_t *buf, endianness_t file_endianness);
uint32_t read_u32(const uint8_t *buf, endianness_t file_endianness);
uint64_t read_u64(const uint8_t *buf, endianness_t file_endianness);

#endif
