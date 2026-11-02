#include "protocol_parser.h"

extern endianness_t file_endianness;

static icmp_t *parse_icmp(const packet_t *packet, size_t offset, size_t payload_length) {
    icmp_t *icmp = malloc(sizeof(icmp_t));

    icmp->type = packet->packet_data[offset + ICMP_TYPE_OFFSET];
    icmp->code = packet->packet_data[offset + ICMP_CODE_OFFSET];
    icmp->checksum = read_u16(packet->packet_data + offset + ICMP_CHECKSUM_OFFSET, file_endianness);
    icmp->rest_of_header = read_u32(packet->packet_data + offset + ICMP_REST_OF_HEADER_OFFSET, file_endianness);

    icmp->payload_offset = offset + ICMP_HEADER_SIZE;

    if (payload_length > ICMP_HEADER_SIZE)
        icmp->payload_length = payload_length - ICMP_HEADER_SIZE;
    else
        icmp->payload_length = 0;

    return icmp;
}



static tcp_t *parse_tcp(const packet_t *packet, size_t offset, size_t payload_length) {
    tcp_t *tcp = malloc(sizeof(tcp_t));

    tcp->source_port = read_u16(packet->packet_data + offset + TCP_SOURCE_PORT_OFFSET, file_endianness);
    tcp->destination_port = read_u16(packet->packet_data + offset + TCP_DESTINATION_PORT_OFFSET, file_endianness);

    tcp->sequence_number = read_u32(packet->packet_data + offset + TCP_SEQUENCE_NUMBER_OFFSET, file_endianness);
    tcp->acknowledgment_number = read_u32(packet->packet_data + offset + TCP_ACKNOWLEDGMENT_NUMBER_OFFSET, file_endianness);

    tcp->data_offset = (packet->packet_data[offset + TCP_DATA_OFFSET] >> TCP_DATA_OFFSET_SHIFT) & TCP_DATA_OFFSET_MASK;

    tcp->ns = packet->packet_data[offset + TCP_DATA_OFFSET] & TCP_NS_MASK;
    tcp->cwr = packet->packet_data[offset + TCP_FLAGS_OFFSET] & TCP_CWR_MASK;
    tcp->ece = packet->packet_data[offset + TCP_FLAGS_OFFSET] & TCP_ECE_MASK;
    tcp->urg = packet->packet_data[offset + TCP_FLAGS_OFFSET] & TCP_URG_MASK;
    tcp->ack = packet->packet_data[offset + TCP_FLAGS_OFFSET] & TCP_ACK_MASK;
    tcp->psh = packet->packet_data[offset + TCP_FLAGS_OFFSET] & TCP_PSH_MASK;
    tcp->rst = packet->packet_data[offset + TCP_FLAGS_OFFSET] & TCP_RST_MASK;
    tcp->syn = packet->packet_data[offset + TCP_FLAGS_OFFSET] & TCP_SYN_MASK;
    tcp->fin = packet->packet_data[offset + TCP_FLAGS_OFFSET] & TCP_FIN_MASK;

    tcp->window_size = read_u16(packet->packet_data + offset + TCP_WINDOW_SIZE_OFFSET, file_endianness);
    tcp->checksum = read_u16(packet->packet_data + offset + TCP_CHECKSUM_OFFSET, file_endianness);
    tcp->urgent_pointer = read_u16(packet->packet_data + offset + TCP_URGENT_POINTER_OFFSET, file_endianness);

    size_t tcp_header_length = tcp->data_offset * 4;

    tcp->options_offset = offset + TCP_HEADER_MIN_SIZE;

    tcp->options_length = tcp_header_length - TCP_HEADER_MIN_SIZE;

    tcp->has_mss = 0;
    tcp->maximum_segment_size = 0;

    tcp->has_window_scale = 0;
    tcp->window_scale = 0;

    tcp->sack_permitted = 0;
    tcp->sack_block_count = 0;

    tcp->has_timestamp = 0;
    tcp->timestamp_value = 0;
    tcp->timestamp_echo_reply = 0;

    size_t position = 0;

    while (position < tcp->options_length) {
        uint8_t kind =
            packet->packet_data[tcp->options_offset + position];

        if (kind == TCP_OPTION_EOL)
            break;

        if (kind == TCP_OPTION_NOP) {
            position++;
            continue;
        }

        uint8_t length =
            packet->packet_data[
                tcp->options_offset + position + 1
            ];

        size_t option_offset =
            tcp->options_offset + position;

        if (kind == TCP_OPTION_MSS &&
            length == TCP_OPTION_MSS_LENGTH) {

            tcp->has_mss = 1;

            tcp->maximum_segment_size =
                read_u16(
                    packet->packet_data + option_offset + 2,
                    file_endianness
                );
        }

        else if (kind == TCP_OPTION_WINDOW_SCALE &&
                 length == TCP_OPTION_WINDOW_SCALE_LENGTH) {

            tcp->has_window_scale = 1;

            tcp->window_scale =
                packet->packet_data[option_offset + 2];
        }

        else if (kind == TCP_OPTION_SACK_PERMITTED &&
                 length == TCP_OPTION_SACK_PERMITTED_LENGTH) {

            tcp->sack_permitted = 1;
        }

        else if (kind == TCP_OPTION_SACK &&
                 length >= TCP_OPTION_SACK_BLOCK_LENGTH + 2) {

            size_t sack_data_length =
                length - 2;

            size_t block_count =
                sack_data_length / TCP_OPTION_SACK_BLOCK_LENGTH;

            for (size_t i = 0;
                 i < block_count &&
                 tcp->sack_block_count < TCP_MAX_SACK_BLOCKS;
                 i++) {

                size_t block_offset =
                    option_offset +
                    2 +
                    (i * TCP_OPTION_SACK_BLOCK_LENGTH);

                tcp->sack_blocks[tcp->sack_block_count].left_edge =
                    read_u32(
                        packet->packet_data + block_offset,
                        file_endianness
                    );

                tcp->sack_blocks[tcp->sack_block_count].right_edge =
                    read_u32(
                        packet->packet_data + block_offset + 4,
                        file_endianness
                    );

                tcp->sack_block_count++;
            }
        }

        else if (kind == TCP_OPTION_TIMESTAMP &&
                 length == TCP_OPTION_TIMESTAMP_LENGTH) {

            tcp->has_timestamp = 1;

            tcp->timestamp_value =
                read_u32(
                    packet->packet_data + option_offset + 2,
                    file_endianness
                );

            tcp->timestamp_echo_reply =
                read_u32(
                    packet->packet_data + option_offset + 6,
                    file_endianness
                );
        }

        position += length;
    }

    tcp->payload_offset =
        offset + tcp_header_length;

    tcp->payload_length =
        payload_length - tcp_header_length;

    return tcp;
}

udp_t *parse_udp(const packet_t *packet, size_t offset)
{
    udp_t *udp = malloc(sizeof(udp_t));

    udp->source_port = read_u16(packet->packet_data + offset + UDP_SOURCE_PORT_OFFSET, file_endianness);
    udp->destination_port = read_u16(packet->packet_data + offset + UDP_DESTINATION_PORT_OFFSET, file_endianness);
    udp->length = read_u16(packet->packet_data + offset + UDP_LENGTH_OFFSET, file_endianness);
    udp->checksum = read_u16(packet->packet_data + offset + UDP_CHECKSUM_OFFSET, file_endianness);

    size_t udp_header_length = UDP_HEADER_SIZE;

    udp->payload_offset = offset + udp_header_length;
    udp->payload_length = udp->length - udp_header_length;

    return udp;
}

void *parse_protocol(const packet_t *packet, uint8_t protocol, size_t offset, size_t payload_length)
{
    switch (protocol) {
        case IP_PROTOCOL_ICMP: return parse_icmp(packet, offset, payload_length);
        case IP_PROTOCOL_TCP: return parse_tcp(packet, offset, payload_length);
        case IP_PROTOCOL_UDP: return parse_udp(packet, offset);
        default: return NULL;
    }
}