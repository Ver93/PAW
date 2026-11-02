#ifndef SHB_PARSER_H
#define SHB_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcapng_blocks.h"
#include "constants.h"
#include "types.h"
#include "endianness.h"
#include "debug.h"
#include "utils.h"

int parse_shb(FILE *f, shb_t *shb);

#endif