#include<cstdio>
#include<fstream>
#include<string>
#include<ctime>
#include<map>
#include<memory>
#include<RawPacket.h>
#include<Packet.h>
#include<IPv4Layer.h>
#include<json/json.h>
#include<PcapFileDevice.h>

const char* Usage = \
"IPMap [input] [output] [setting path]\n"
"Map all ips according to the specific settings.\n";

typedef struct _config{
    std::map<u_int32_t, u_int32_t> ip_map;
} Config;

typedef std::shared_ptr<Config> PConfig;

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
        in_addr_t src = pcpp::IPv4Address(name).toInt();
        in_addr_t dst = pcpp::IPv4Address(config_json[name].asCString()).toInt();
        config->ip_map[src] = dst;
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
    pcpp::RawPacket rpkt;
    u_int64_t count=0;
    u_int64_t write_count = 0;
    clock_t t = clock();
    while(reader->getNextPacket(rpkt)){
        count++;
        pcpp::Packet pkt(&rpkt);
        auto ipv4 = pkt.getLayerOfType<pcpp::IPv4Layer>();
        if(ipv4 != nullptr) {
            u_int32_t src = ipv4->getSrcIpAddress().toInt();
            u_int32_t dst = ipv4->getDstIpAddress().toInt();
            if(config->ip_map.count(src) == 1)
                ipv4->setSrcIpAddress(pcpp::IPv4Address(config->ip_map[src]));
            if(config->ip_map.count(dst) == 1)
                ipv4->setDstIpAddress(pcpp::IPv4Address(config->ip_map[dst]));
        }else
            printf("Warning: %lld packet doesn't have an ipv4 layer.\n", count);
        write_count++;
        writer.writePacket(rpkt);
    }
    writer.close();
    reader->close();
    printf("Done! Write %lld packets of %lld packets in %f seconds",
           write_count, count, ((double)clock() - (double)t)/CLOCKS_PER_SEC);
}