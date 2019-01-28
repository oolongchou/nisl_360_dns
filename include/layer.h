typedef struct _ether_hdr{
    u_int8_t source_mac[6];
    u_int8_t destination_mac[6];
    u_int16_t type;
} ether_hdr;

// RFC791 3.1
typedef struct _ip_hdr{
    // see http://mjfrazer.org/mjfrazer/bitfields/
    //     https://elixir.bootlin.com/linux/v4.20.5/source/include/uapi/linux/ip.h#L86
    //     https://stackoverflow.com/questions/47600584/bitfield-endianness-in-gcc
    // bytes are big-endian, but bits may be little-endian (depends on how compiler implements it).
    // little-endian works on my machine and perhaps on most machines :).
    u_int8_t header_length:4;
    u_int8_t version:4;
    u_int8_t service_type;
    u_int16_t total_length;
    u_int16_t identification;
    u_int16_t fragment_offset;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t checksum;
    u_int32_t source;
    u_int32_t destination;
    // we don't care about options.
} ip_hdr;

// RFC768
typedef struct _udp_hdr{
    u_int16_t source_port;
    u_int16_t destination_port;
    u_int16_t length;
    u_int16_t checksum;
} udp_hdr;

typedef struct _fake_hdr{
    u_int32_t source;
    u_int32_t destination;
    u_int8_t zero;
    u_int8_t protocol;
    u_int16_t length;
} fake_hdr;

// RFC793 3.1
typedef struct _tcp_hdr{
    u_int16_t source_port;
    u_int16_t destination_port;
    u_int32_t sequence_number;
    u_int32_t acknowldgement_number;
    // see https://elixir.bootlin.com/linux/v4.20.5/source/include/uapi/linux/tcp.h#L25
    u_int16_t reserve:4;
    u_int16_t data_offset:4;
    u_int16_t fin:1,
              syn:1,
              rst:1,
              psh:1,
              ack:1,
              urg:1,
              ece:1,
              cwr:1;
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgent_pointer;
    // again, we don't care about options.
} tcp_hdr;
