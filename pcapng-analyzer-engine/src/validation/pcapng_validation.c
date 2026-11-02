#include "pcapng_validation.h"
#include "constants.h"

#include <stdio.h>

int validate_shb(const shb_t *shb) {
    if (shb->block_type != SHB) {
        printf("SHB: invalid block_type\n");
        return 1;
    }

    if (shb->block_length < PCAPNG_SHB_MIN_LENGTH ||
        shb->block_length > PCAPNG_MAX_BLOCK_LENGTH) {
        printf("SHB: invalid block_length\n");
        return 1;
    }

    if (shb->byte_order_magic != PCAPNG_BYTE_ORDER_MAGIC_LE &&
        shb->byte_order_magic != PCAPNG_BYTE_ORDER_MAGIC_BE) {
        printf("SHB: invalid byte_order_magic\n");
        return 1;
    }

    if (shb->major_version != PCAPNG_MAJOR_VERSION ||
        shb->minor_version != PCAPNG_MINOR_VERSION) {
        printf("SHB: invalid version\n");
        return 1;
    }

    if (shb->block_footer != shb->block_length) {
        printf("SHB: invalid block_footer\n");
        return 1;
    }

    if (shb->section_length == 0) {
        printf("SHB: invalid section_length\n");
        return 1;
    }

    return 0;
}


int validate_idb(const idb_t *idb) {
    if (idb->block_type != IDB) {
        printf("IDB: invalid block_type\n");
        return 1;
    }

    if (idb->block_length < PCAPNG_IDB_MIN_LENGTH ||
        idb->block_length > PCAPNG_MAX_BLOCK_LENGTH) {
        printf("IDB: invalid block_length\n");
        return 1;
    }

    if (idb->block_footer != idb->block_length) {
        printf("IDB: invalid block_footer\n");
        return 1;
    }

    return 0;
}


int validate_epb(const epb_t *epb) {
    if (epb->block_type != EPB) {
        printf("EPB: invalid block_type\n");
        return 1;
    }

    if (epb->block_length < PCAPNG_EPB_MIN_LENGTH ||
        epb->block_length > PCAPNG_MAX_BLOCK_LENGTH) {
        printf("EPB: invalid block_length\n");
        return 1;
    }

    if (epb->block_footer != epb->block_length) {
        printf("EPB: invalid block_footer\n");
        return 1;
    }

    if (epb->captured_packet_length >
        epb->original_packet_length) {
        printf("EPB: captured > original length\n");
        return 1;
    }

    if (epb->packet_data == NULL &&
        epb->captured_packet_length > 0) {
        printf("EPB: missing packet_data\n");
        return 1;
    }

    return 0;
}


int validate_pb(const pb_t *pb) {
    if (pb->block_type != PB) {
        printf("PB: invalid block_type\n");
        return 1;
    }

    if (pb->block_length < PCAPNG_PB_MIN_LENGTH ||
        pb->block_length > PCAPNG_MAX_BLOCK_LENGTH) {
        printf("PB: invalid block_length\n");
        return 1;
    }

    if (pb->block_footer != pb->block_length) {
        printf("PB: invalid block_footer\n");
        return 1;
    }

    if (pb->captured_packet_length >
        pb->original_packet_length) {
        printf("PB: captured > original length\n");
        return 1;
    }

    if (pb->packet_data == NULL &&
        pb->captured_packet_length > 0) {
        printf("PB: missing packet_data\n");
        return 1;
    }

    return 0;
}


int validate_spb(const spb_t *spb){
    if (spb->block_type != SPB) {
        printf("SPB: invalid block_type\n");
        return 1;
    }

    if (spb->block_length < PCAPNG_SPB_MIN_LENGTH ||
        spb->block_length > PCAPNG_MAX_BLOCK_LENGTH) {
        printf("SPB: invalid block_length\n");
        return 1;
    }

    if (spb->block_footer != spb->block_length) {
        printf("SPB: invalid block_footer\n");
        return 1;
    }

    if (spb->captured_packet_length >
        spb->original_packet_length) {
        printf("SPB: captured > original length\n");
        return 1;
    }

    if (spb->packet_data == NULL &&
        spb->captured_packet_length > 0) {
        printf("SPB: missing packet_data\n");
        return 1;
    }

    return 0;
}


int validate_pcapng(const pcapng_t *pcapng){
    int errors = 0;

    if (validate_shb(&pcapng->shb) != 0) {
        printf("PCAPNG: SHB validation failed\n");
        errors++;
    }

    for (size_t i = 0; i < pcapng->interface_count; i++) {

        if (validate_idb(&pcapng->interfaces[i]) != 0) {
            printf("PCAPNG: IDB[%zu] validation failed\n", i);

            errors++;
        }
    }

    for (size_t i = 0; i < pcapng->epb_count; i++) {

        const epb_t *epb = &pcapng->epbs[i];

        if (validate_epb(epb) != 0) {
            printf("PCAPNG: EPB[%zu] validation failed\n", i);

            errors++;
        }

        if (epb->interface_id >= pcapng->interface_count) {
            printf("PCAPNG: EPB[%zu] references non-existing interface\n", i);

            errors++;
        }
    }

    for (size_t i = 0; i < pcapng->pb_count; i++) {

        const pb_t *pb = &pcapng->pbs[i];

        if (validate_pb(pb) != 0) {
            printf("PCAPNG: PB[%zu] validation failed\n", i);

            errors++;
        }

        if (pb->interface_id >= pcapng->interface_count) {
            printf("PCAPNG: PB[%zu] references non-existing interface\n", i);

            errors++;
        }
    }

    for (size_t i = 0; i < pcapng->spb_count; i++) {

        const spb_t *spb = &pcapng->spbs[i];

        if (validate_spb(spb) != 0) {
            printf("PCAPNG: SPB[%zu] validation failed\n", i);

            errors++;
        }
    }

    for (size_t i = 0;
         i < pcapng->name_resolution_block_count;
         i++) {

        const nrb_t *nrb =
            &pcapng->name_resolution_blocks[i];

        if (nrb->block_type != NRB) {
            printf("PCAPNG: NRB[%zu] invalid block_type\n", i);

            errors++;
        }

        if (nrb->block_length < PCAPNG_NRB_MIN_LENGTH ||
            nrb->block_length > PCAPNG_MAX_BLOCK_LENGTH) {

            printf("PCAPNG: NRB[%zu] invalid block_length\n", i);

            errors++;
        }

        if (nrb->block_footer != nrb->block_length) {
            printf("PCAPNG: NRB[%zu] invalid block_footer\n", i);

            errors++;
        }
    }

    for (size_t i = 0;
         i < pcapng->interface_statistics_block_count;
         i++) {

        const isb_t *isb =
            &pcapng->interface_statistics_blocks[i];

        if (isb->block_type != ISB) {
            printf("PCAPNG: ISB[%zu] invalid block_type\n", i);

            errors++;
        }

        if (isb->block_length < PCAPNG_ISB_MIN_LENGTH ||
            isb->block_length > PCAPNG_MAX_BLOCK_LENGTH) {

            printf("PCAPNG: ISB[%zu] invalid block_length\n", i);

            errors++;
        }

        if (isb->interface_id >= pcapng->interface_count) {
            printf("PCAPNG: ISB[%zu] references non-existing interface\n", i);

            errors++;
        }

        if (isb->block_footer != isb->block_length) {
            printf("PCAPNG: ISB[%zu] invalid block_footer\n", i);

            errors++;
        }
    }

    if (pcapng->interface_count == 0) {
        printf("PCAPNG: No IDB found after SHB\n");
        errors++;
    }

    if (errors == 0) {
        printf("PCAPNG: Validation OK\n");
        return 0;
    }

    printf("PCAPNG: Validation failed with %d error(s)\n", errors);

    return errors;
}