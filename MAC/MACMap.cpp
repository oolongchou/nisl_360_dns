#include<cstdio>
#include<cstdlib>
#include<cstring>
#include<fstream>
#include<string>
#include<ctime>
#include<random>
#include<set>
#include<map>
#include<memory>
#include<RawPacket.h>
#include<Packet.h>
#include<EthLayer.h>
#include<json/json.h>
#include<PcapFileDevice.h>

const char* Usage = \
"MACMap [input] [output] [setting path]\n"
"Map all MAC address OUI to specific OUI (see oui.txt) and randomize last 24 bits if necessary.\n";

typedef struct _config{
    pcpp::MacAddress from;
    pcpp::MacAddress to;
} Config;

typedef std::shared_ptr<Config> PConfig;

PConfig read_config(const char* path){
    std::fstream fs(path, std::ios::in);
    if(!fs.is_open()){
        return nullptr;
    }
    Json::Value config_json;
    try{
        fs >> config_json;
    }catch (const std::exception& e){
        printf("%s\n", e.what());
        return nullptr;
    }
    if(!config_json.isMember("From") || !config_json.isMember("To"))
        return nullptr;
    else
        return PConfig(new Config{config_json["From"].asString(), config_json["To"].asString()});
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
    std::fstream fs(std::string(output) + ".map.json", std::ios::out|std::ios::trunc);
    if(!fs.is_open()){
        printf("Fail to open output map json file.\n");
        exit(0);
    }
    Json::Value mac_map;
    pcpp::RawPacket rpkt;
    u_int64_t count=0;
    u_int64_t write_count = 0;
    clock_t t = clock();
    while(reader->getNextPacket(rpkt)){
        count++;
        pcpp::Packet pkt(&rpkt);
        auto eth = pkt.getLayerOfType<pcpp::EthLayer>();
        if(eth != nullptr) {
            auto src_mac = eth->getSourceMac().toString();
            auto dst_mac = eth->getDestMac().toString();
            if(mac_map.isMember(src_mac))
                eth->setSourceMac(pcpp::MacAddress(mac_map[src_mac].asString()));
            else{
                mac_map[src_mac] = config->from.toString();
                eth->setSourceMac(config->from);
            }
            if(mac_map.isMember(dst_mac))
                eth->setDestMac(pcpp::MacAddress(mac_map[dst_mac].asString()));
            else{
                mac_map[dst_mac] = config->to.toString();
                eth->setDestMac(config->to);
            }
        }else
            printf("Warning: %lld packet doesn't have an eth layer.\n", count);
        write_count++;
        writer.writePacket(rpkt);
    }
    fs << mac_map;
    writer.close();
    reader->close();
    printf("Done! Write %lld packets of %lld packets in %f seconds",
           write_count, count, ((double)clock() - (double)t)/CLOCKS_PER_SEC);
}