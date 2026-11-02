#ifndef PCAPNG_H
#define PCAPNG_H

#include "pcapng_blocks.h"

typedef struct {
    shb_t shb;

    idb_t *interfaces;
    size_t interface_count;

    epb_t *epbs;
    size_t epb_count;

    pb_t *pbs;
    size_t pb_count;

    spb_t *spbs;
    size_t spb_count;

    nrb_t *name_resolution_blocks;
    size_t name_resolution_block_count;

    isb_t *interface_statistics_blocks;
    size_t interface_statistics_block_count;

    packet_t *packets;
    size_t packet_count;

} pcapng_t;

#endif