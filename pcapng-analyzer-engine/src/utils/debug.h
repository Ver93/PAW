#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <stdint.h>

extern uint8_t debug;
#define DEBUG_PRINT(...) do { if (debug) fprintf(stderr, "[DEBUG] " __VA_ARGS__); } while(0)

#endif
