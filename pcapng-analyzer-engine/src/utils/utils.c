#include "utils.h"


void byte_to_hex(uint8_t *data, size_t len) {
    for (size_t j = 0; j < len; j++)
        printf("%02X ", data[j]);
}

void hex_to_string(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];
        printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }
}