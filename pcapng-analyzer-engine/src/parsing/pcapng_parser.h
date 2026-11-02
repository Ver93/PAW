#ifndef PCAPNG_PARSER_H
#define PCAPNG_PARSER_H

#include <stdio.h>

#include "pcapng_blocks.h"
#include "shb_parser.h"
#include "idb_parser.h"
#include "epb_parser.h"
#include "isb_parser.h"
#include "nrb_parser.h"
#include "pb_parser.h"
#include "spb_parser.h"
#include "pcapng.h"

int parse_pcapng(FILE *fp, pcapng_t *pcapng);
void free_pcapng(pcapng_t *pcapng);

#endif