#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>

#include "constants.h"

typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
} ethernet_t;

#endif