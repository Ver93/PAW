#ifndef PCAPNG_VALIDATION_H

#define PCAPNG_VALIDATION_H

#include <stdio.h>

#include "pcapng_blocks.h"
#include "pcapng.h"

int validate_shb(const shb_t *shb);
int validate_idb(const idb_t *idb);
int validate_epb(const epb_t *epb);
int validate_pb(const pb_t *pb);
int validate_spb(const spb_t *spb);

int validate_pcapng(const pcapng_t *pcapng);

#endif