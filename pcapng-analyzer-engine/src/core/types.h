#ifndef TYPES_H
#define TYPES_H

typedef enum {
    PARSE_OK = 0,
    PARSE_EOF,
    PARSE_TRUNCATED,
    PARSE_INVALID,
    PARSE_IO_ERROR,
    PARSE_OOM
} parse_result_t;

#endif