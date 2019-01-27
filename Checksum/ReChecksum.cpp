#include<pcap.h>
#include<cstdio>
#include<cstdlib>
#include<cstdint>
#include<arpa/inet.h>
#include<cstring>
#include<ctime>

static const char* Usage = \
"Usage: ReChecksum [input] [output]\n"
"Calculate all checksum of the input pcap file and write new file to output file.\n"
"Implemented: ip, udp, tcp\n";

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

// Perform one's complement addition.
u_int16_t onesComplementAdd(u_int16_t lhs, u_int16_t rhs){
    const u_int32_t mask = (1<<16) - 1;
    const u_int32_t result = (u_int32_t)lhs + (u_int32_t)rhs;
    if(result > mask)
        return (u_int16_t)((result + 1) & mask);
    else
        return (u_int16_t)(result & mask);
}

// Perform checksum for ip, udp, tcp.
// Note: the data `data` points to should be in big endian and returned value is in little endian.
u_int16_t checksum(const u_char *data, int len){
    if(len % 2 != 0)
        return 0;
    u_int16_t result = 0;
    auto p = (const u_int16_t*)(data);
    for(int i = 0; i < len/2; i++)
        result = onesComplementAdd(result, ntohs(p[i]));
    return (u_int16_t)(~result & ((1<<16) -1));
}


int main(int argc, char** argv){
    if(argc != 3) {
        printf("%s", Usage);
        exit(0);
    }
    clock_t t = clock();
    char errbuf[PCAP_ERRBUF_SIZE];
    char* input = argv[1];
    char* output = argv[2];
    auto inputhandle = pcap_open_offline(input, errbuf);
    if(inputhandle == nullptr){
        printf("Open input pcap file failed!\n");
        exit(0);
    }
    auto outputhandle = pcap_dump_open(inputhandle, output);
    if(outputhandle == nullptr){
        printf("Open output pcap file failed!\n");
        exit(0);
    }
    printf("Start to calculate checksum...\n");
    pcap_pkthdr* pkt;
    const u_char* data;
    int result;
    u_int64_t count = 0;
    while((result = pcap_next_ex(inputhandle, &pkt, &data))!= PCAP_ERROR_BREAK){
        count ++;
        auto ether = (ether_hdr*)(data);
        u_int16_t frame_type = ntohs(ether->type);
        if(frame_type == 0x800){ // ipv4 packet
            // ip checksum
            auto ipv4 = (ip_hdr*)(data + sizeof(ether_hdr));
            u_int32_t ip_header_len = ipv4->header_length * (unsigned)4;
            auto origin_ip_checksum = ipv4->checksum;
            ipv4->checksum = 0;
            auto ip_checksum = htons(checksum((const u_char *) ipv4, ip_header_len));
            ipv4->checksum = ip_checksum;
            if(ip_checksum != origin_ip_checksum)
                printf("ip:%X %X\n", origin_ip_checksum, ip_checksum);
            auto udp = [&](){
                return (udp_hdr*)(data + sizeof(ether_hdr) + ip_header_len);
            };
            auto tcp = [&](){
                return (tcp_hdr*)(data + sizeof(ether_hdr) + ip_header_len);
            };
            // tcp and udp checksum
            u_int8_t ip_protocol = ipv4->protocol;
            if(ip_protocol == 17 || ip_protocol == 6) { // 17 for udp and 6 for tcp
                u_int16_t segment_length = ntohs(ipv4->total_length) - (u_int16_t) ip_header_len;
                fake_hdr fhdr{ipv4->source, ipv4->destination, 0, ip_protocol, htons(segment_length)}; // don't forget to convert to big-endian.
                u_int16_t original_transport_checksum = 0;
                u_int32_t transport_header_length = 0;
                u_int32_t data_length = 0;
                if(ip_protocol == 17) {
                    transport_header_length = 8;
                    original_transport_checksum = udp()->checksum;
                    udp()->checksum = 0;
                }
                else{
                    transport_header_length = tcp()->data_offset * (unsigned)4;
                    original_transport_checksum = tcp()->checksum;
                    tcp()->checksum = 0;
                }
                data_length = segment_length - transport_header_length;
                int buffer_len = 0;
                u_char* buffer;
                if(data_length % 2 == 0) {
                    buffer_len = sizeof(fake_hdr) + segment_length;
                    buffer = new u_char[buffer_len];
                }
                else{
                    buffer_len = sizeof(fake_hdr) + segment_length + 1;
                    buffer = new u_char[buffer_len];
                    buffer[buffer_len-1] = 0;
                }
                memcpy(buffer, &fhdr, sizeof(fake_hdr));
                memcpy(buffer+sizeof(fake_hdr), data + sizeof(ether_hdr)+ ip_header_len,segment_length);
                auto transport_checksum = htons(checksum(buffer, buffer_len));
                delete []buffer;
                if(ip_protocol == 17)
                    udp()->checksum = transport_checksum;
                else
                    tcp()->checksum = transport_checksum;
            }
            pcap_dump((u_char*)outputhandle, pkt, data);
        }else if(frame_type == 0x86DD){ // ipv6 packet
            printf("Warning: ipv6 not implemented.\n");
        }else{
            printf("Warning: unknown mac frame type: %X\n", frame_type);
        }
    }
    pcap_close(inputhandle);
    pcap_dump_close(outputhandle);
    printf("Done! Write %lld packets in %f seconds\n", count, ((double)clock() - (double)t)/CLOCKS_PER_SEC);
}
