
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "pcapng_parser.h"
#include "pcapng_validation.h"
#include "packet_parser.h"
#include "packet_validation.h"
#include "protocol_node.h"
#include "json_export.h"
#include "flow.h"
#include "flow_output.h"

int main(int argc, char *argv[]) {

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.pcapng>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");

    if (!fp) {
        perror("Could not open PCAPNG file");
        return 1;
    }

    pcapng_t pcapng = {0};

    parse_pcapng(fp, &pcapng);
    fclose(fp);

    if (validate_pcapng(&pcapng) != 0) {
        free_pcapng(&pcapng);
        return 1;
    }

    parse_packets(&pcapng);

    if (validate_packets(&pcapng) != 0) {
        free_pcapng(&pcapng);
        return 1;
    }

    protocol_chain_t **chains = build_all_chains(&pcapng);

    if (!chains) {
        free_pcapng(&pcapng);
        return 1;
    }

    flow_table_t flow_table = {0};
    init_flow_table(&flow_table);

    for (size_t i = 0; i < pcapng.packet_count; i++) {

        if (chains[i]) {

            print_protocol_nodes_json(chains[i], i);

            analyze_flow(
                &pcapng.packets[i],
                chains[i],
                &flow_table,
                i
            );
        }
    }

    print_flows_json(&flow_table);

    free_flow_table(&flow_table);
    free_pcapng(&pcapng);
    free_all_chains(chains);

    return 0;
}
