#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "pcapng_parser.h"
#include "pcapng_validation.h"
#include "packet_parser.h"
#include "packet_validation.h"

#include "protocol_node.h"

int main(int argc, char *argv[]){
    
    if (argc < 2) return 1;

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 1;

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

    free_pcapng(&pcapng);
    free_all_chains(chains);

    return 0;
}
