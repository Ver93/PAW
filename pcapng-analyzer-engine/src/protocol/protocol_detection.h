#ifndef PROTOCOL_DETECTION_H
#define PROTOCOL_DETECTION_H

#include <stddef.h>
#include <stdint.h>

#include "protocol_node.h"

typedef struct {
    protocol_type_t protocol;
    int confidence;
    int port_match;
    int payload_match;
} protocol_detection_t;

typedef struct {
    protocol_detection_t *detections;
    size_t count;
} protocol_detection_list_t;

void protocol_detection_list_init(
    protocol_detection_list_t *list
);

void protocol_detection_list_free(
    protocol_detection_list_t *list
);

int detect_application_protocols(
    uint8_t transport_protocol,
    uint16_t source_port,
    uint16_t destination_port,
    const uint8_t *payload,
    size_t payload_length,
    protocol_detection_list_t *result
);

#endif