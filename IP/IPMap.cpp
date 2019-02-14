#include<cstdio>
#include<fstream>
#include<string>
#include<ctime>
#include<map>
#include<memory>
#include<random>
#include<RawPacket.h>
#include<Packet.h>
#include<IPv4Layer.h>
#include<DnsLayer.h>
#include<json/json.h>
#include<PcapFileDevice.h>

const char* Usage = \
"IPMap [input] [output] [setting path]\n"
"Map all ips according to the specific settings.\n"
"Implemented: src and dst in ip layer, ip of A record answer in dns layer\n";

typedef struct _config{
    std::map<u_int32_t, u_int32_t> ipv4_map;
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
    for(auto& name : config_json.getMemberNames()){
        map_json[name] = config_json[name].asString();
        in_addr_t src = pcpp::IPv4Address(name).toInt();
        in_addr_t dst = pcpp::IPv4Address(config_json[name].asCString()).toInt();
        config->ipv4_map[src] = dst;
    }
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
    auto generate_valid_ipv4_address = [&](){
        u_int32_t result = g();
        while(!((result & 0xFF) && (result & 0xFF00) && (result & 0xFF0000) && (result & 0xFF000000)))
            result = g();
        return result;
    };
    auto generate_random_ip_and_map = [&](u_int32_t original_ip){
        u_int32_t random_ip = generate_valid_ipv4_address();
        config->ipv4_map[original_ip] = random_ip;
        map_json[pcpp::IPv4Address(original_ip).toString()] = pcpp::IPv4Address(random_ip).toString();
        return random_ip;
    };
    auto set_ip_if_not_mapped = [&](u_int32_t& ip){
        if(config->ipv4_map.count(ip) == 1)
            ip = config->ipv4_map[ip];
        else
            ip = generate_random_ip_and_map(ip);
    };
    while(reader->getNextPacket(rpkt)){
        count++;
        pcpp::Packet pkt(&rpkt);
        auto ipv4 = pkt.getLayerOfType<pcpp::IPv4Layer>();
        if(ipv4 != nullptr) {
            set_ip_if_not_mapped(ipv4->getIPv4Header()->ipSrc);
            set_ip_if_not_mapped(ipv4->getIPv4Header()->ipDst);
            auto dns = pkt.getLayerOfType<pcpp::DnsLayer>();
            auto process_resource = [&](pcpp::DnsResource& res){
                auto dns_type = res.getDnsType();
                if(dns_type == pcpp::DnsType::DNS_TYPE_A){
                    u_int32_t answer_ip = pcpp::IPv4Address(res.getDataAsString()).toInt();
                    if(config->ipv4_map.count(answer_ip) == 1)
                        res.setData(pcpp::IPv4Address(config->ipv4_map[answer_ip]).toString());
                    else
                        res.setData(pcpp::IPv4Address(generate_random_ip_and_map(answer_ip)).toString());
                }else if(dns_type == pcpp::DnsType::DNS_TYPE_AAAA){
                    printf("Warning: ipv6 answer detected in %lld packet.\n", count);
                }
            };
            if(dns != nullptr) {
                for (auto it = dns->getFirstAnswer(); it != nullptr; it = dns->getNextAnswer(it))
                    process_resource(*it);
                for (auto it = dns->getFirstAdditionalRecord(); it != nullptr; it = dns->getNextAdditionalRecord(it))
                    process_resource(*it);
            }
        }else
            printf("Warning: %lld packet doesn't have an ipv4 layer.\n", count);
        write_count++;
        writer.writePacket(rpkt);
    }
    fs << map_json;
    writer.close();
    reader->close();
    printf("Done! Write %lld packets of %lld packets in %f seconds",
           write_count, count, ((double)clock() - (double)t)/CLOCKS_PER_SEC);
}