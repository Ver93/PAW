#ifndef APPLICATION_PROTOCOL_H
#define APPLICATION_PROTOCOL_H

#include <stdint.h>
#include "protocol_node.h"

protocol_type_t detect_application_protocol(
    uint8_t transport_protocol,
    uint16_t source_port,
    uint16_t destination_port,
    const uint8_t *payload,
    size_t payload_length
);

#endif