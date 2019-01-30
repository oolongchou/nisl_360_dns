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
    bool to_randomize;
    u_int8_t oui[3];
} Config;

typedef std::shared_ptr<Config> PConfig;

bool parse_oui(const std::string& oui, u_int8_t* buffer, size_t len){
    size_t cnt = 0;
    for(size_t i = 0; i < oui.length() && cnt < len;) {
        auto next_semicolon = oui.find('-', i);
        if(next_semicolon == std::string::npos)
            next_semicolon = oui.length();
        buffer[cnt] = (u_int8_t)strtol(oui.substr(i, next_semicolon - i).c_str(), nullptr, 16);
        i = next_semicolon + 1;
        cnt ++;
    }
    return cnt == len;
}

u_int32_t next_unique(){
    static std::set<u_int32_t> pool;
    static u_int32_t mask = (1 << 24) - 1;
    std::random_device rd;
    std::mt19937 g(rd());
    u_int32_t next = g() & mask;
    while(pool.count(next) == 1)
        next = g();
    pool.insert(next);
    return next;
}

pcpp::MacAddress generate_next_mac(const pcpp::MacAddress& mac,const PConfig& config){
    u_int8_t fourth, fifth, sixth;
    if(config->to_randomize) {
        u_int32_t last = next_unique();
        fourth = (u_int8_t) (last & 0xFF);
        fifth = (u_int8_t) (last & 0xFF00);
        sixth = (u_int8_t) (last & 0xFF0000);
    }else{
        u_int8_t mac_addr[6];
        mac.copyTo(mac_addr);
        fourth = mac_addr[3];
        fifth = mac_addr[4];
        sixth = mac_addr[5];
    }
    return pcpp::MacAddress(config->oui[0], config->oui[1], config->oui[2], fourth, fifth, sixth);
}

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
    if(!config_json.isMember("Randomize"))
        config->to_randomize = true;
    else
        config->to_randomize = config_json["Randomize"].asBool();
    if(config_json.isMember("OUIReplace")){
        u_int8_t oui[3];
        if(!parse_oui(config_json["OUIReplace"].asString(), oui, 3))
            return nullptr;
        else
            memcpy(config->oui, oui, 3);
    }else
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
            u_int8_t buffer[6];
            auto src_mac = eth->getSourceMac();
            if(mac_map.isMember(src_mac.toString()))
                eth->setSourceMac(mac_map[src_mac.toString()].asString());
            else {
                auto new_mac = generate_next_mac(src_mac, config);
                eth->setSourceMac(new_mac);
                mac_map[src_mac.toString()] = new_mac.toString();
            }
            auto dst_mac = eth->getDestMac();
            if(mac_map.isMember(dst_mac.toString()))
                eth->setDestMac(mac_map[dst_mac.toString()].asString());
            else {
                auto new_mac = generate_next_mac(dst_mac, config);
                eth->setDestMac(new_mac);
                mac_map[dst_mac.toString()] = new_mac.toString();
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