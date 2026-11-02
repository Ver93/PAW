#ifndef ISB_PARSER_H
#define ISB_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcapng_blocks.h"
#include "constants.h"
#include "types.h"
#include "endianness.h"
#include "debug.h"
#include "utils.h"

int parse_isb(FILE *f, isb_t *shb);

#endif