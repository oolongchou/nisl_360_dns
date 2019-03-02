#include<pcap.h>
#include<cstdio>
#include<cstdlib>
#include<cstdint>
#include<arpa/inet.h>
#include<cstring>
#include<ctime>
#include<RawPacket.h>
#include<Packet.h>
#include<IPv4Layer.h>
#include<TcpLayer.h>
#include<UdpLayer.h>

static const char* Usage = \
"Usage: ReChecksum [input] [output]\n"
"Calculate all checksum of the input pcap file and write new file to output file.\n"
"Implemented: ip, udp, tcp\n";

typedef struct _fake_hdr{
    u_int32_t source;
    u_int32_t destination;
    u_int8_t zero;
    u_int8_t protocol;
    u_int16_t length;
} fake_hdr;

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
    pcap_pkthdr* pkthdr;
    const u_char* data;
    int result;
    u_int64_t count = 0;
    u_int64_t write_count = 0;
    while((result = pcap_next_ex(inputhandle, &pkthdr, &data))!= PCAP_ERROR_BREAK){
        count ++;
        pcpp::RawPacket rpkt(data, pkthdr->caplen, pkthdr->ts, false);
        pcpp::Packet pkt(&rpkt);
        auto ipv4 = pkt.getLayerOfType<pcpp::IPv4Layer>();
        if(ipv4 == nullptr) {
            printf("Warning: %lld packet is not an ipv4 packet.", count);
            continue;
        }
        auto ip_header_len = (u_int32_t)ipv4->getHeaderLen();
        auto origin_ip_checksum = ipv4->getIPv4Header()->headerChecksum;
        ipv4->getIPv4Header()->headerChecksum = 0;
        auto ip_checksum = htons(checksum((const u_char *) ipv4->getData(), ip_header_len));
        ipv4->getIPv4Header()->headerChecksum = ip_checksum;
#ifdef DEBUG
        if(ip_checksum != origin_ip_checksum)
            printf("ip:%X %X\n", origin_ip_checksum, ip_checksum);
#endif
        auto udp = pkt.getLayerOfType<pcpp::UdpLayer>();
        auto tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
        // tcp and udp checksum
        if(udp != nullptr || tcp != nullptr) {
            auto segment_length = (u_int32_t)ipv4->getDataLen() - ip_header_len;
            fake_hdr fhdr{
                ipv4->getIPv4Header()->ipSrc,
                ipv4->getIPv4Header()->ipDst,
                0,
                ipv4->getIPv4Header()->protocol,
                htons(segment_length)}; // don't forget to convert to big-endian.
            u_int16_t original_transport_checksum = 0;
            u_int32_t transport_header_length = 0;
            u_int32_t data_length = 0;
            if(udp != nullptr) {
                transport_header_length = 8;
                original_transport_checksum = udp->getUdpHeader()->headerChecksum;
                udp->getUdpHeader()->headerChecksum = 0;
            }
            else{
                transport_header_length = (u_int32_t)tcp->getHeaderLen();
                original_transport_checksum = tcp->getTcpHeader()->headerChecksum;
                tcp->getTcpHeader()->headerChecksum = 0;
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
            memcpy(buffer+sizeof(fake_hdr), ipv4->getData() + ip_header_len, segment_length);
            auto transport_checksum = htons(checksum(buffer, buffer_len));
            delete []buffer;
            if(udp != nullptr)
                udp->getUdpHeader()->headerChecksum = transport_checksum;
            else
                tcp->getTcpHeader()->headerChecksum = transport_checksum;
#ifdef DEBUG
            if(original_transport_checksum != transport_checksum)
                printf("tdp/udp: %X %X\n", original_transport_checksum, transport_checksum);
#endif
        }
        write_count++;
        pcap_dump((u_char*)outputhandle, pkthdr, data);
    }
    pcap_close(inputhandle);
    pcap_dump_close(outputhandle);
    printf("Done! Write %lld packets of %lld packets in %f seconds\n",
            write_count, count, ((double)clock() - (double)t)/CLOCKS_PER_SEC);
}
