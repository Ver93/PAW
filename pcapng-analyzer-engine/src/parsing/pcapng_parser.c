#include "pcapng_parser.h"
#include "endianness.h"
#include <stdlib.h>

int parse_pcapng(FILE *f, pcapng_t *pcapng) {
    
    int result = parse_shb(f, &pcapng->shb);
    if (result != PARSE_OK)
        return result;

    while (1) {
        uint32_t block_type;

        if (fread(&block_type, sizeof(block_type), 1, f) != 1)
            break;

        if (file_endianness != get_system_endianness())
            block_type = swap32(block_type);

        if (fseek(f, -4, SEEK_CUR) != 0)
            return PARSE_IO_ERROR;

        switch (block_type) {

        case IDB: {
            
            idb_t idb = {0};
            if ((result = parse_idb(f, &idb)) != PARSE_OK) return result;

            idb_t *tmp = realloc(pcapng->interfaces, (pcapng->interface_count + 1) * sizeof(idb_t));         
            if (!tmp) return PARSE_OOM;

            pcapng->interfaces = tmp;
            pcapng->interfaces[pcapng->interface_count++] = idb;
            break;
        }

        case EPB: {
            epb_t epb = {0};

            if ((result = parse_epb(f, &epb)) != PARSE_OK) return result;

            packet_t packet = {0};
            packet.block_type = epb.block_type;
            packet.interface_id = epb.interface_id;
            packet.link_type = pcapng->interfaces[epb.interface_id].link_type;
            packet.timestamp_high = epb.timestamp_high;
            packet.timestamp_low = epb.timestamp_low;
            packet.captured_packet_length = epb.captured_packet_length;
            packet.original_packet_length = epb.original_packet_length;
            packet.options = epb.options;
            packet.options_count = epb.options_count;
            packet.packet_data = epb.packet_data;

            packet_t *tmp = realloc(pcapng->packets, (pcapng->packet_count + 1) * sizeof(packet_t));
            
            if (!tmp) {
                free(packet.packet_data);
                return PARSE_OOM;
            }

            pcapng->packets = tmp;
            pcapng->packets[pcapng->packet_count++] = packet;
            break;
        }

        case NRB: {
            nrb_t nrb = {0};
            if ((result = parse_nrb(f, &nrb)) != PARSE_OK)
                return result;

            nrb_t *tmp = realloc(pcapng->name_resolution_blocks,
                                 (pcapng->name_resolution_block_count + 1) * sizeof(nrb_t));
            if (!tmp)
                return PARSE_OOM;

            pcapng->name_resolution_blocks = tmp;
            pcapng->name_resolution_blocks[pcapng->name_resolution_block_count++] = nrb;
            break;
        }

        case ISB: {
            isb_t isb = {0};
            if ((result = parse_isb(f, &isb)) != PARSE_OK)
                return result;

            isb_t *tmp = realloc(pcapng->interface_statistics_blocks,
                                 (pcapng->interface_statistics_block_count + 1) * sizeof(isb_t));
            if (!tmp)
                return PARSE_OOM;

            pcapng->interface_statistics_blocks = tmp;
            pcapng->interface_statistics_blocks[pcapng->interface_statistics_block_count++] = isb;
            break;
        }

        case PB: {
            pb_t pb = {0};
            if ((result = parse_pb(f, &pb)) != PARSE_OK)
                return result;

            packet_t packet = {0};
            packet.block_type = pb.block_type;
            packet.interface_id = pb.interface_id;
            packet.link_type = pcapng->interfaces[pb.interface_id].link_type;
            packet.timestamp_high = pb.timestamp_high;
            packet.timestamp_low = pb.timestamp_low;
            packet.captured_packet_length = pb.captured_packet_length;
            packet.original_packet_length = pb.original_packet_length;
            packet.options = pb.options;
            packet.options_count = pb.options_count;
            packet.packet_data = pb.packet_data;

            packet_t *tmp = realloc(pcapng->packets,
                                    (pcapng->packet_count + 1) * sizeof(packet_t));
            if (!tmp) {
                free(packet.packet_data);
                return PARSE_OOM;
            }

            pcapng->packets = tmp;
            pcapng->packets[pcapng->packet_count++] = packet;

            for (size_t i = 0; i < pb.options_count; i++)
                free(pb.options[i].value);
            free(pb.options);

            break;
        }

        case SPB: {
            spb_t spb = {0};
            if ((result = parse_spb(f, &spb)) != PARSE_OK)
                return result;

            packet_t packet = {0};
            packet.block_type = spb.block_type;
            packet.interface_id = 0;
            packet.link_type = pcapng->interfaces[0].link_type;
            packet.timestamp_high = 0;
            packet.timestamp_low = 0;
            packet.captured_packet_length = spb.captured_packet_length;
            packet.original_packet_length = spb.original_packet_length;
            packet.packet_data = spb.packet_data;

            packet_t *tmp = realloc(pcapng->packets,
                                    (pcapng->packet_count + 1) * sizeof(packet_t));
            if (!tmp) {
                free(packet.packet_data);
                return PARSE_OOM;
            }

            pcapng->packets = tmp;
            pcapng->packets[pcapng->packet_count++] = packet;
            break;
        }

        default:
            return PARSE_INVALID;
        }
    }

    return PARSE_OK;
}

void free_options(options_t *options, size_t options_count)
{
    if (!options)
        return;

    for (size_t i = 0; i < options_count; i++)
        free(options[i].value);

    free(options);
}

void free_pcapng(pcapng_t *pcapng)
{
    if (!pcapng)
        return;

    free_options(pcapng->shb.options, pcapng->shb.options_count);

    free(pcapng->interfaces);

    for (size_t i = 0; i < pcapng->epb_count; i++) {
        free(pcapng->epbs[i].packet_data);
        free_options(pcapng->epbs[i].options, pcapng->epbs[i].options_count);
    }
    free(pcapng->epbs);

    for (size_t i = 0; i < pcapng->pb_count; i++) {
        free(pcapng->pbs[i].packet_data);
        free_options(pcapng->pbs[i].options, pcapng->pbs[i].options_count);
    }
    free(pcapng->pbs);

    for (size_t i = 0; i < pcapng->spb_count; i++)
        free(pcapng->spbs[i].packet_data);
    free(pcapng->spbs);

    for (size_t i = 0; i < pcapng->name_resolution_block_count; i++) {
        nrb_t *nrb = &pcapng->name_resolution_blocks[i];
        for (size_t j = 0; j < nrb->record_count; j++)
            free(nrb->records[j].record_value);
        free(nrb->records);
    }
    free(pcapng->name_resolution_blocks);

    for (size_t i = 0; i < pcapng->interface_statistics_block_count; i++)
        free_options(pcapng->interface_statistics_blocks[i].options,
                     pcapng->interface_statistics_blocks[i].options_count);
    free(pcapng->interface_statistics_blocks);

    free(pcapng->packets);

    *pcapng = (pcapng_t){0};
}
