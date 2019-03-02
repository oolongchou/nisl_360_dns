#include<cstdio>
#include<fstream>
#include<string>
#include<cstring>
#include<ctime>
#include<map>
#include<memory>
#include<random>
#include "RawPacket.h"
#include<Packet.h>
#include<netinet/in.h>
#include<IPv4Layer.h>
#include<IPv6Layer.h>
#include<TcpLayer.h>
#include<DnsLayer.h>
#include<json/json.h>
#include<PcapFileDevice.h>

const char* Usage = \
"IPMap [input] [output] [setting path]\n"
"Map all ips according to the specific settings.\n"
"Implemented: src and dst in ip layer, ip of A record answer in dns layer\n";

// Make in6_addr comparable.
class in6_addr_compare{
public:
    bool operator()(const in6_addr& lhs, const in6_addr& rhs) const{
        return ((const u_int8_t*)(&lhs))[0] < ((const u_int8_t*)(&rhs))[0];
    }
};

typedef struct _config{
    std::map<u_int32_t, u_int32_t> ipv4_map;
    std::map<in6_addr, in6_addr, in6_addr_compare> ipv6_map;
    in6_addr prefix;
    u_int32_t prefix_len;
} Config;

typedef std::shared_ptr<Config> PConfig;

static Json::Value map_json;

PConfig read_config(const char* path){
    std::fstream fs(path, std::ios::in);
    if(!fs.is_open()){
        return nullptr;
    }
    Json::Value config_json;
    PConfig config(new Config);
    try{
        fs >> config_json;
    }catch (const std::exception& e){
        printf("%s\n", e.what());
        return nullptr;
    }
    if(config_json.isMember("ipv4")) {
        for (auto &name : config_json["ipv4"].getMemberNames()) {
            map_json["ipv4"][name] = config_json[name].asString();
            in_addr_t src = pcpp::IPv4Address(name).toInt();
            in_addr_t dst = pcpp::IPv4Address(config_json["ipv4"][name].asCString()).toInt();
            config->ipv4_map[src] = dst;
        }
    }
    if(config_json.isMember("ipv6")){
        for(auto& name : config_json["ipv6"].getMemberNames()){
            map_json["ipv6"][name] = config_json[name].asString();
            auto src = pcpp::IPv6Address(name).toIn6Addr();
            auto dst = pcpp::IPv6Address(config_json["ipv6"][name].asString()).toIn6Addr();
            config->ipv6_map[*src] = *dst;
        }
    }
    if(!config_json.isMember("Prefix") || !config_json.isMember("PrefixLen"))
        return nullptr;
    config->prefix = *pcpp::IPv6Address(config_json["Prefix"].asString()).toIn6Addr();
    config->prefix_len = config_json["PrefixLen"].asUInt();
    if(config->prefix_len > 128)
        return nullptr;
    return config;
}

int main(int argc, char** argv) {
    if(argc != 4){
        printf("%s", Usage);
        exit(0);
    }
    auto input = argv[1];
    auto output = argv[2];
    auto setting_path = argv[3];
    auto config = read_config(setting_path);
    if(config == nullptr){
        printf("Fail to read config.\n");
        exit(0);
    }
    auto reader = pcpp::IFileReaderDevice::getReader(input);
    if(reader == nullptr || !reader->open()){
        printf("Fail to open input pcap file.\n");
        exit(0);
    }
    pcpp::PcapFileWriterDevice writer(output);
    if(!writer.open()){
        printf("Fail to open output pcap file.\n");
        exit(0);
    }
    std::fstream fs(std::string(output) + ".map.json", std::ios::out | std::ios::trunc);
    if(!fs.is_open()){
        printf("Fail to open output map file.\n");
        exit(0);
    }
    std::random_device rd;
    std::mt19937 g(rd());
    pcpp::RawPacket rpkt;
    u_int64_t count=0;
    u_int64_t write_count = 0;
    clock_t t = clock();
    bool to_write = true;
    auto generate_valid_ipv4_address = [&](){
        u_int32_t result = g();
        while(!((result & 0xFF) && (result & 0xFF00) && (result & 0xFF0000) && (result & 0xFF000000)))
            result = g();
        return result;
    };
    auto generate_valid_ipv6_address = [&](){
        in6_addr result{0};
        auto result_p32 = (u_int32_t*)&result;
        for(int i = 0; i<4;i++){
            auto random_int = g();
            while(random_int == 0)
                random_int = g();
            result_p32[i] = random_int;
        }
        auto result_p8 = (u_int8_t*)result_p32;
        auto prefix_len = config->prefix_len;
        auto prefix_p8 = ((u_int8_t*)(&config->prefix));
        auto left = prefix_len & 0x7; // prefix_len % 8
        auto prefix_bytes = prefix_len/8;
        for(int i = 0; i < prefix_bytes ;i ++)
            result_p8[i] = prefix_p8[i];
        result_p8[prefix_bytes] &= (1 << (8-left)) -1;
        result_p8[prefix_bytes] |= prefix_p8[prefix_bytes] & (~((1 << (8-left)) -1));
        return result;
    };
    auto generate_random_ipv4_and_map = [&](u_int32_t original_ip){
        u_int32_t random_ip = generate_valid_ipv4_address();
        config->ipv4_map[original_ip] = random_ip;
        map_json["ipv4"][pcpp::IPv4Address(original_ip).toString()] = pcpp::IPv4Address(random_ip).toString();
        return random_ip;
    };
    auto generate_random_ipv6_and_map = [&](const in6_addr& original_ipv6){
        auto random_ipv6 = generate_valid_ipv6_address();
        config->ipv6_map[original_ipv6] = random_ipv6;
        map_json["ipv6"][pcpp::IPv6Address((u_int8_t*)(&original_ipv6)).toString()] = pcpp::IPv6Address((u_int8_t*)(&random_ipv6)).toString();
        return random_ipv6;
    };
    auto set_ipv4_if_not_mapped = [&](u_int32_t& ip){
        if(config->ipv4_map.count(ip) == 1)
            ip = config->ipv4_map[ip];
        else
            ip = generate_random_ipv4_and_map(ip);
    };
    auto set_ipv6_if_not_mapped = [&](in6_addr& ip){
        if(config->ipv6_map.count(ip) == 1)
            ip = config->ipv6_map[ip];
        else
            ip = generate_random_ipv6_and_map(ip);
    };
    while(reader->getNextPacket(rpkt)){
        count++;
        to_write = true;
        pcpp::Packet pkt(&rpkt);
        auto ipv4 = pkt.getLayerOfType<pcpp::IPv4Layer>();
        auto ipv6 = pkt.getLayerOfType<pcpp::IPv6Layer>();
        auto dns = pkt.getLayerOfType<pcpp::DnsLayer>();
        auto tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
        auto process_resource = [&](pcpp::DnsResource& res){
            auto dns_type = res.getDnsType();
            if(dns_type == pcpp::DnsType::DNS_TYPE_A){
                u_int32_t answer_ip = pcpp::IPv4Address(res.getDataAsString()).toInt();
                if(config->ipv4_map.count(answer_ip) == 1)
                    res.setData(pcpp::IPv4Address(config->ipv4_map[answer_ip]).toString());
                else
                    res.setData(pcpp::IPv4Address(generate_random_ipv4_and_map(answer_ip)).toString());
            }else if(dns_type == pcpp::DnsType::DNS_TYPE_AAAA){
                auto answer_ip = *pcpp::IPv6Address(res.getDataAsString()).toIn6Addr();
                if(config->ipv6_map.count(answer_ip) == 1)
                    res.setData(pcpp::IPv6Address((u_int8_t*)(&config->ipv6_map[answer_ip])).toString());
                else {
                    auto mapped_ipv6 = generate_random_ipv6_and_map(answer_ip);
                    res.setData(pcpp::IPv6Address((u_int8_t *)&mapped_ipv6).toString());
                }
            }
        };
        if(ipv4 != nullptr) {
            set_ipv4_if_not_mapped(ipv4->getIPv4Header()->ipSrc);
            set_ipv4_if_not_mapped(ipv4->getIPv4Header()->ipDst);
        }else if(ipv6 != nullptr){
            set_ipv6_if_not_mapped(*((in6_addr*)ipv6->getIPv6Header()->ipSrc));
            set_ipv6_if_not_mapped(*((in6_addr*)ipv6->getIPv6Header()->ipDst));
        }else
            printf("Warning: %lld packet doesn't contain a valid ip layer.\n", count);
        std::shared_ptr<pcpp::DnsLayer> pdns;
        if(dns == nullptr && tcp != nullptr && tcp->getDataLen() - tcp->getHeaderLen() >= sizeof(pcpp::dnshdr)) {
            auto tcp_layer_len = tcp->getDataLen();
            auto tcp_header_len = tcp->getHeaderLen();
            auto dns_packet_length = ntohs(((u_int16_t*)(tcp->getData() + tcp_header_len))[0]);
            /*
             * RFC 1035 4.2.2
             *
             * The message is prefixed with a two byte length field which gives the message length, excluding the two byte length field.
             *
             */
            if(dns_packet_length != tcp_layer_len - tcp_header_len - 2){
                dns = nullptr;
                to_write = false;
            }else {
                /*
                 * We have to do this since the copy constructor of pcpp::DnsLayer will copy all data.
                 */
                pdns = std::make_shared<pcpp::DnsLayer>(tcp->getData() + tcp_header_len + 2, dns_packet_length, tcp, &pkt);
                dns = pdns.get();
            }
        }
        if(dns != nullptr) {
            for (auto it = dns->getFirstAnswer(); it != nullptr; it = dns->getNextAnswer(it))
                process_resource(*it);
            for (auto it = dns->getFirstAdditionalRecord(); it != nullptr; it = dns->getNextAdditionalRecord(it))
                process_resource(*it);
        }
        if(to_write) {
            write_count++;
            rpkt.setRawDataLen(rpkt.getFrameLength());
            writer.writePacket(rpkt);
        }
    }
    fs << map_json;
    writer.close();
    reader->close();
    printf("Done! Write %lld packets of %lld packets in %f seconds",
           write_count, count, ((double)clock() - (double)t)/CLOCKS_PER_SEC);
}