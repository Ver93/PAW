#ifndef IPV4_REASSEMBLY_VALIDATION_H
#define IPV4_REASSEMBLY_VALIDATION_H

#include <stdlib.h>

#include "ipv4_reassembly.h"

ipv4_reassembly_status_t validate_fragment_group(const ipv4_fragment_group_t *group);

#endif