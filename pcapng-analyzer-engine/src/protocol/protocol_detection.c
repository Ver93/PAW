#include "protocol_detection.h"

#include <stdlib.h>
#include <string.h>

#include "application_protocol.h"

typedef int (*payload_match_fn)(
    const uint8_t *payload,
    size_t payload_length
);

typedef struct {
    protocol_type_t protocol;

    uint8_t transport_protocol;

    const uint16_t *ports;
    size_t port_count;

    payload_match_fn match_payload;

    int port_score;
    int payload_score;
} protocol_detector_t;


/*
 * ------------------------------------------------------------
 * Generic helpers
 * ------------------------------------------------------------
 */

static int port_matches(
    const protocol_detector_t *detector,
    uint16_t source_port,
    uint16_t destination_port
) {
    if (!detector)
        return 0;

    for (size_t i = 0; i < detector->port_count; i++) {

        uint16_t port = detector->ports[i];

        if (source_port == port ||
            destination_port == port) {

            return 1;
        }
    }

    return 0;
}


static int append_detection(
    protocol_detection_list_t *list,
    protocol_type_t protocol,
    int confidence,
    int port_match,
    int payload_match
) {
    protocol_detection_t *new_detections =
        realloc(
            list->detections,
            sizeof(protocol_detection_t) *
            (list->count + 1)
        );

    if (!new_detections)
        return 0;

    list->detections = new_detections;

    protocol_detection_t *detection =
        &list->detections[list->count];

    detection->protocol = protocol;
    detection->confidence = confidence;
    detection->port_match = port_match;
    detection->payload_match = payload_match;

    list->count++;

    return 1;
}


/*
 * ------------------------------------------------------------
 * Payload matching
 * ------------------------------------------------------------
 */

static int match_ftp(
    const uint8_t *payload,
    size_t payload_length
) {
    return detect_ftp_payload(
        payload,
        payload_length
    );
}


static int match_smtp(
    const uint8_t *payload,
    size_t payload_length
) {
    return detect_smtp_payload(
        payload,
        payload_length
    );
}


/*
 * ------------------------------------------------------------
 * Protocol definitions
 * ------------------------------------------------------------
 */

static const uint16_t ftp_ports[] = {
    21
};

static const uint16_t smtp_ports[] = {
    25,
    587
};

static const protocol_detector_t detectors[] = {

    {
        .protocol = PROTO_FTP,
        .transport_protocol = IP_PROTOCOL_TCP,

        .ports = ftp_ports,
        .port_count = 1,

        .match_payload = match_ftp,

        .port_score = 20,
        .payload_score = 80
    },

    {
        .protocol = PROTO_SMTP,
        .transport_protocol = IP_PROTOCOL_TCP,

        .ports = smtp_ports,
        .port_count = 2,

        .match_payload = match_smtp,

        .port_score = 20,
        .payload_score = 80
    }
};


#define DETECTOR_COUNT \
    (sizeof(detectors) / sizeof(detectors[0]))


/*
 * ------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------
 */

void protocol_detection_list_init(
    protocol_detection_list_t *list
) {
    if (!list)
        return;

    list->detections = NULL;
    list->count = 0;
}


void protocol_detection_list_free(
    protocol_detection_list_t *list
) {
    if (!list)
        return;

    free(list->detections);

    list->detections = NULL;
    list->count = 0;
}


int detect_application_protocols(
    uint8_t transport_protocol,
    uint16_t source_port,
    uint16_t destination_port,
    const uint8_t *payload,
    size_t payload_length,
    protocol_detection_list_t *result
) {
    if (!result)
        return 0;

    protocol_detection_list_init(result);

    for (size_t i = 0; i < DETECTOR_COUNT; i++) {

        const protocol_detector_t *detector =
            &detectors[i];

        if (detector->transport_protocol !=
            transport_protocol) {

            continue;
        }

        int port_match =
            port_matches(
                detector,
                source_port,
                destination_port
            );

        int payload_match = 0;

        if (payload &&
            payload_length > 0 &&
            detector->match_payload) {

            payload_match =
                detector->match_payload(
                    payload,
                    payload_length
                );
        }

        if (!port_match &&
            !payload_match) {

            continue;
        }

        int confidence = 0;

        if (port_match)
            confidence += detector->port_score;

        if (payload_match)
            confidence += detector->payload_score;

        if (!append_detection(
                result,
                detector->protocol,
                confidence,
                port_match,
                payload_match)) {

            protocol_detection_list_free(result);
            return 0;
        }
    }

    return 1;
}