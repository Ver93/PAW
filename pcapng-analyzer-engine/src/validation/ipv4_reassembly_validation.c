#include <stdint.h>
#include <stdlib.h>

#include "ipv4_reassembly_validation.h"

static int compare_fragments(const void *a, const void *b)
{
    const ipv4_fragment_t *fragment_a =
        *(const ipv4_fragment_t **)a;

    const ipv4_fragment_t *fragment_b =
        *(const ipv4_fragment_t **)b;

    if (fragment_a->offset < fragment_b->offset)
        return -1;

    if (fragment_a->offset > fragment_b->offset)
        return 1;

    return 0;
}

static int fragments_conflict(
    const ipv4_fragment_t *a,
    const ipv4_fragment_t *b)
{
    if (!a || !b || !a->data || !b->data)
        return 0;

    if (a->length >
        SIZE_MAX - a->offset)
        return 1;

    if (b->length >
        SIZE_MAX - b->offset)
        return 1;

    size_t a_end =
        a->offset + a->length;

    size_t b_end =
        b->offset + b->length;

    size_t overlap_start =
        a->offset > b->offset
        ? a->offset
        : b->offset;

    size_t overlap_end =
        a_end < b_end
        ? a_end
        : b_end;

    if (overlap_start >= overlap_end)
        return 0;

    for (size_t offset = overlap_start;
         offset < overlap_end;
         offset++) {

        size_t a_index =
            offset - a->offset;

        size_t b_index =
            offset - b->offset;

        if (a->data[a_index] !=
            b->data[b_index])
            return 1;
    }

    return 0;
}

ipv4_reassembly_status_t validate_fragment_group(
    const ipv4_fragment_group_t *group)
{
    if (!group || group->fragment_count == 0)
        return IPV4_REASSEMBLY_INCOMPLETE;

    qsort(group->fragments,
          group->fragment_count,
          sizeof(ipv4_fragment_t *),
          compare_fragments);

    size_t current_offset = 0;
    int last_fragment_found = 0;

    for (size_t i = 0;
         i < group->fragment_count;
         i++) {

        ipv4_fragment_t *fragment =
            group->fragments[i];

        if (!fragment)
            return IPV4_REASSEMBLY_INCOMPLETE;

        if (fragment->length == 0)
            return IPV4_REASSEMBLY_INCOMPLETE;

        if (fragment->length >
            SIZE_MAX - fragment->offset)
            return IPV4_REASSEMBLY_INCOMPLETE;

        size_t fragment_start =
            fragment->offset;

        size_t fragment_end =
            fragment->offset +
            fragment->length;

        if (fragment_start < current_offset) {
            for (size_t j = 0; j < i; j++) {
                if (fragments_conflict(
                        group->fragments[j],
                        fragment))
                    return IPV4_REASSEMBLY_CONFLICT;
            }

            return IPV4_REASSEMBLY_OVERLAP;
        }

        if (fragment_start > current_offset)
            return IPV4_REASSEMBLY_INCOMPLETE;

        current_offset = fragment_end;

        if (!fragment->more_fragments) {
            if (i != group->fragment_count - 1)
                return IPV4_REASSEMBLY_INCOMPLETE;

            last_fragment_found = 1;
        }
    }

    if (!last_fragment_found)
        return IPV4_REASSEMBLY_INCOMPLETE;

    return IPV4_REASSEMBLY_COMPLETE;
}