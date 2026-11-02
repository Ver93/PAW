#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipv4_reassembly.h"
#include "ipv4_reassembly_validation.h"

static ipv4_fragment_group_t *create_group(void)
{
    ipv4_fragment_group_t *group =
        calloc(1, sizeof(ipv4_fragment_group_t));

    if (!group)
        return NULL;

    group->identification = 1234;
    group->protocol = 17;

    memset(group->source_ip, 192, sizeof(group->source_ip));
    memset(group->destination_ip, 10, sizeof(group->destination_ip));

    return group;
}

static int add_test_fragment(
    ipv4_fragment_group_t *group,
    size_t offset,
    size_t length,
    int more_fragments,
    uint8_t value)
{
    ipv4_fragment_t *fragment =
        malloc(sizeof(ipv4_fragment_t));

    if (!fragment)
        return 0;

    memset(fragment, 0, sizeof(ipv4_fragment_t));

    memcpy(fragment->source_ip,
           group->source_ip,
           sizeof(fragment->source_ip));

    memcpy(fragment->destination_ip,
           group->destination_ip,
           sizeof(fragment->destination_ip));

    fragment->identification =
        group->identification;

    fragment->protocol =
        group->protocol;

    fragment->offset = offset;
    fragment->length = length;
    fragment->more_fragments = more_fragments;

    if (length > 0) {
        fragment->data = malloc(length);

        if (!fragment->data) {
            free(fragment);
            return 0;
        }

        memset((void *)fragment->data,
               value,
               length);
    }

    return add_fragment(group, fragment);
}

static void free_group(ipv4_fragment_group_t *group)
{
    if (!group)
        return;

    for (size_t i = 0;
         i < group->fragment_count;
         i++) {

        if (group->fragments[i]) {
            free((void *)group->fragments[i]->data);
            free(group->fragments[i]);
        }
    }

    free(group->fragments);
    free(group);
}


/*
 * Existing tests
 */

static int test_missing_fragment(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * [0,    1480) MF=1
     * [2960, 4440) MF=0
     *
     * Missing [1480, 2960)
     */
    add_test_fragment(group, 0, 1480, 1, 0x11);
    add_test_fragment(group, 2960, 1480, 0, 0x22);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status == IPV4_REASSEMBLY_INCOMPLETE;
}

static int test_overlap(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * [0,    1480)
     * [1400, 2400)
     *
     * Overlap [1400, 1480)
     */
    add_test_fragment(group, 0, 1480, 1, 0x11);
    add_test_fragment(group, 1400, 1000, 0, 0x11);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status == IPV4_REASSEMBLY_OVERLAP;
}

static int test_wrong_order(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    add_test_fragment(group, 1480, 1480, 0, 0x22);
    add_test_fragment(group, 0, 1480, 1, 0x11);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status == IPV4_REASSEMBLY_COMPLETE;
}

static int test_conflict(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * Same range, different data.
     */
    add_test_fragment(group, 0, 1480, 1, 0x11);
    add_test_fragment(group, 0, 1480, 1, 0x22);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status == IPV4_REASSEMBLY_CONFLICT;
}

static int test_duplicate(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    add_test_fragment(group, 0, 1480, 1, 0x11);
    add_test_fragment(group, 0, 1480, 1, 0x11);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status == IPV4_REASSEMBLY_OVERLAP;
}

static int test_multiple_last_fragments(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * [0,    1480) MF=0
     * [1480, 2960) MF=0
     */
    add_test_fragment(group, 0, 1480, 0, 0x11);
    add_test_fragment(group, 1480, 1480, 0, 0x22);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status == IPV4_REASSEMBLY_INCOMPLETE;
}

static int test_fragment_after_last(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * [0,    1480) MF=1
     * [1480, 2960) MF=0
     * [2960, 4440) MF=0
     */
    add_test_fragment(group, 0, 1480, 1, 0x11);
    add_test_fragment(group, 1480, 1480, 0, 0x22);
    add_test_fragment(group, 2960, 1480, 0, 0x33);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status == IPV4_REASSEMBLY_INCOMPLETE;
}


/*
 * New tests
 */

static int test_missing_last_fragment(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * Every fragment has MF=1.
     *
     * There is no final fragment.
     */
    add_test_fragment(group, 0, 1480, 1, 0x11);
    add_test_fragment(group, 1480, 1480, 1, 0x22);
    add_test_fragment(group, 2960, 1480, 1, 0x33);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status == IPV4_REASSEMBLY_INCOMPLETE;
}

static int test_missing_first_fragment(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * Starts at offset 1480 instead of 0.
     */
    add_test_fragment(group, 1480, 1480, 1, 0x11);
    add_test_fragment(group, 2960, 1480, 0, 0x22);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status == IPV4_REASSEMBLY_INCOMPLETE;
}

static int test_gap_between_fragments(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * [0,    1480)
     * [1600, 2960)
     *
     * Missing [1480, 1600)
     */
    add_test_fragment(group, 0, 1480, 1, 0x11);
    add_test_fragment(group, 1600, 1360, 0, 0x22);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status == IPV4_REASSEMBLY_INCOMPLETE;
}

static int test_zero_length_fragment(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * A zero-length fragment must not create
     * a valid reassembly range.
     */
    add_test_fragment(group, 0, 0, 1, 0x11);
    add_test_fragment(group, 0, 1480, 0, 0x22);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status != IPV4_REASSEMBLY_COMPLETE;
}

static int test_zero_length_last_fragment(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * Last fragment has zero payload.
     */
    add_test_fragment(group, 0, 1480, 1, 0x11);
    add_test_fragment(group, 1480, 0, 0, 0x22);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status != IPV4_REASSEMBLY_COMPLETE;
}

static int test_unaligned_fragment_offset(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * IPv4 fragment offsets are expressed in
     * 8-byte units.
     *
     * Offset 1481 is invalid.
     */
    add_test_fragment(group, 0, 1480, 1, 0x11);
    add_test_fragment(group, 1481, 1480, 0, 0x22);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status != IPV4_REASSEMBLY_COMPLETE;
}

static int test_offset_length_overflow(void)
{
    ipv4_fragment_group_t *group =
        create_group();

    if (!group)
        return 0;

    /*
     * Force offset + length to overflow size_t.
     */
    size_t offset =
        (size_t)-100;

    size_t length =
        200;

    add_test_fragment(
        group,
        offset,
        length,
        0,
        0x11);

    ipv4_reassembly_status_t status =
        validate_fragment_group(group);

    free_group(group);

    return status != IPV4_REASSEMBLY_COMPLETE;
}


int main(void)
{
    int passed = 0;
    int failed = 0;

    printf("IPv4 REASSEMBLY TESTS\n");
    printf("=============================\n");

    if (test_missing_fragment() != 0) {
        printf("Missing fragment:               PASS\n");
        passed++;
    } else {
        printf("Missing fragment:               FAIL\n");
        failed++;
    }

    if (test_overlap() != 0) {
        printf("Overlap:                        PASS\n");
        passed++;
    } else {
        printf("Overlap:                        FAIL\n");
        failed++;
    }

    if (test_wrong_order() != 0) {
        printf("Wrong order:                    PASS\n");
        passed++;
    } else {
        printf("Wrong order:                    FAIL\n");
        failed++;
    }

    if (test_conflict() != 0) {
        printf("Conflict:                       PASS\n");
        passed++;
    } else {
        printf("Conflict:                       FAIL\n");
        failed++;
    }

    if (test_duplicate() != 0) {
        printf("Duplicate:                      PASS\n");
        passed++;
    } else {
        printf("Duplicate:                      FAIL\n");
        failed++;
    }

    if (test_multiple_last_fragments() != 0) {
        printf("Multiple last fragments:        PASS\n");
        passed++;
    } else {
        printf("Multiple last fragments:        FAIL\n");
        failed++;
    }

    if (test_fragment_after_last() != 0) {
        printf("Fragment after last:            PASS\n");
        passed++;
    } else {
        printf("Fragment after last:            FAIL\n");
        failed++;
    }

    if (test_missing_last_fragment() != 0) {
        printf("Missing last fragment:          PASS\n");
        passed++;
    } else {
        printf("Missing last fragment:          FAIL\n");
        failed++;
    }

    if (test_missing_first_fragment() != 0) {
        printf("Missing first fragment:         PASS\n");
        passed++;
    } else {
        printf("Missing first fragment:         FAIL\n");
        failed++;
    }

    if (test_gap_between_fragments() != 0) {
        printf("Gap between fragments:          PASS\n");
        passed++;
    } else {
        printf("Gap between fragments:          FAIL\n");
        failed++;
    }

    if (test_zero_length_fragment() != 0) {
        printf("Zero-length fragment:           PASS\n");
        passed++;
    } else {
        printf("Zero-length fragment:           FAIL\n");
        failed++;
    }

    if (test_zero_length_last_fragment() != 0) {
        printf("Zero-length last fragment:      PASS\n");
        passed++;
    } else {
        printf("Zero-length last fragment:      FAIL\n");
        failed++;
    }

    if (test_unaligned_fragment_offset() != 0) {
        printf("Unaligned fragment offset:      PASS\n");
        passed++;
    } else {
        printf("Unaligned fragment offset:      FAIL\n");
        failed++;
    }

    if (test_offset_length_overflow() != 0) {
        printf("Offset + length overflow:       PASS\n");
        passed++;
    } else {
        printf("Offset + length overflow:       FAIL\n");
        failed++;
    }

    printf("\nPassed: %d\n", passed);
    printf("Failed: %d\n", failed);

    return failed != 0;
}