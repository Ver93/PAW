#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdio.h>

#include "types.h"

void byte_to_hex(uint8_t *data, size_t len);
void hex_to_string(uint8_t *hex, size_t len);

#endif