#include<cstdio>
#include<functional>
#include<memory>
#include<fstream>
#include<string>
#include<ctime>
#include<algorithm>
#include<map>
#include<vector>
#include<set>
#include<RawPacket.h>
#include<Packet.h>
#include<sstream>
#include"CustomDnsLayer.h"
#include<TcpLayer.h>
#include<json/json.h>
#include<PcapFileDevice.h>
#include<openssl/sha.h>

static const size_t digest_len = SHA256_DIGEST_LENGTH;

typedef struct _config{
    bool to_lowercase;
    bool to_hash;
    bool preserve_last;
    std::vector<std::string> deletions;
    std::vector<std::string> constants;
    std::map<std::string, std::string> replacements;
} Config;

typedef std::shared_ptr<unsigned char> Digest;

typedef Digest Buffer;

typedef std::shared_ptr<Config> PConfig;


bool lhsEndsWithrhs(const std::string& lhs, const std::string& rhs){
    if(lhs.length() < rhs.length())
        return false;
    return lhs.compare(lhs.length() - rhs.length(), rhs.length(), rhs) == 0;
}

Digest hash(const char* str, u_int64_t len){
    auto buffer = new unsigned char[digest_len];
    SHA256((const unsigned char*)str, len, buffer);
    Digest digest(buffer, [](const unsigned char* p){delete []p;});
    return digest;
}

std::string format_digest(const Digest& digest, size_t len=digest_len){
    std::string result(2*len, '|');
    for(int i = 0; i< len;i++){
        char buffer[3];
        snprintf(buffer, 3, "%02x", digest.get()[i]);
        result[2*i] = buffer[0];
        result[2*i+1] = buffer[1];
    }
    return result;
}

bool plain_match(const std::string& needle, const std::vector<std::string>& haystack){
    for(auto& s : haystack)
        if(lhsEndsWithrhs(needle, s))
            return true;
    return false;
}

std::vector<std::string> split(const std::string& str, char delim = '.'){
    std::vector<std::string> result;
    size_t last = 0;
    size_t dot = 0;
    while((dot = str.find(delim, last))!=std::string::npos) {
        if(dot != last)
            result.emplace_back(str.substr(last, dot - last));
        last = dot + 1;
    }
    if(last != str.length())
        result.emplace_back(str.substr(last));
    return result;
}

std::string join(const std::vector<std::string>& v, char delim = '.'){
    std::stringstream ss;
    for(auto it = v.begin(); it != v.end(); it ++){
        if(it != v.end() - 1)
            ss << *it << delim;
        else
            ss << *it;
    }
    return ss.str();
}

std::string replace_domain(const std::string &domain, const std::map<std::string, std::string> &replacements, const PConfig& config){
    std::string result = domain;
    std::string suffix;
    for(auto& it : replacements) {
        std::string replacement = it.first;
        if (lhsEndsWithrhs(domain, replacement)) {
            result = domain.substr(0, domain.length() - replacement.length());
            suffix = it.second;
            break;
        }
    }
    auto result_tokens = split(result);
    auto suffix_tokens = split(suffix);
    std::stringstream ss;
    if(config->to_hash)
        for(auto it = result_tokens.begin(); it != result_tokens.end(); it ++)
            if(!(config->preserve_last && result_tokens.size() > 1 && it == result_tokens.begin()))
                *it = format_digest(hash(it->c_str(), it->length())).substr(0, it->length());
    for(auto& it : suffix_tokens)
        result_tokens.emplace_back(it);
    return join(result_tokens);
}

void write_domain(
        u_int8_t *dns_data,
        size_t dns_data_length,
        u_int8_t *start_address,
        const std::string &domain,
        int iter = 0){
    assert(iter <= 20);
    size_t pos = 0;
    size_t last = 0;
    u_int8_t* pstart = start_address;
    while(true){
        if(pos == domain.length()) // .com.cn
            break;
        pos = domain.find('.', last);
        if(pos == std::string::npos){
            if(last == domain.length()) // .com.cn.
                break;
            else
                pos = domain.length(); // .com.cn (on more iteration)
        }
        auto len = pstart[0];
        if((len & 0xc0) == 0xc0){
            auto offset = ((len & 0x3f) << 8) + (0xFF & pstart[1]);
            write_domain(dns_data, dns_data_length, dns_data + offset, domain.substr(last), iter + 1);
            break; // one domain can only contain one pointer.
        }else{
            std::string segment = domain.substr(last, pos - last);
            assert(len == segment.length());
            memcpy(pstart+1, segment.c_str(), len);
            last = pos + 1;
            pstart += (len + 1);
        }
    }
}

PConfig read_config(const char* path){
    std::fstream fs(path, std::ios::in);
    PConfig config(new Config);
    if(!fs.is_open())
        return nullptr;
    Json::Value config_json;
    try{
        fs >> config_json;
    }catch(const std::exception& e){
        printf("%s\n", e.what());
        return nullptr;
    }
    config->to_lowercase = config_json.get("ToLowercase", true).asBool();
    if(config_json.isMember("Replacements")){
        auto replacements = config_json["Replacements"];
        for(auto& name : replacements.getMemberNames())
            config->replacements[name] = replacements[name].asString();
    }
    if(config_json.isMember("Deletions")){
        auto deletions = config_json["Deletions"];
        for(auto& it: deletions)
            config->deletions.emplace_back(it.asString());
    }
    if(config_json.isMember("Constants")){
        auto constants = config_json["Constants"];
        for(auto& it: constants)
            config->constants.emplace_back(it.asString());
    }
    if(!config_json.isMember("ToHash") || !config_json.isMember("PreserveLast"))
        return nullptr;
    config->preserve_last = config_json["PreserveLast"].asBool();
    config->to_hash = config_json["ToHash"].asBool();
    return config;
}

const char* Usage = \
"DomainMap [input] [output] [setting path]\n"
"Hash all domains in dns query in the input pcap file and write to output pcap with the map.\n"
"The specified suffix will be replaced with new suffix and thus won't be hashed.\n"
"Note: A json containing the domains map will be also created.\n"
"      See settings.json for how to configure.\n";

int main(int argc, char** argv){
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
    Json::Value map;
    pcpp::RawPacket rpkt;
    std::set<u_int16_t> to_delete;
    u_int64_t count=0;
    u_int64_t write_count = 0;
    clock_t t = clock();
    while(reader->getNextPacket(rpkt)){
        count++;
        bool to_write = true;
        pcpp::Packet pkt(&rpkt);
        auto dns = pkt.getLayerOfType<pcpp::DnsLayer>();
        auto tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
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
        if(dns != nullptr){
            u_int16_t tid = dns->getDnsHeader()->transactionID;
            if(to_delete.count(tid) == 1){
                to_delete.erase(tid);
                to_write = false;
            }else {
                // not elegant at all. :(
                auto buffer = Buffer(new unsigned char[dns->getDataLen()], [](const unsigned char* p){delete []p;});
                memcpy(buffer.get(), dns->getData(), dns->getDataLen());
                auto delete_if_match = [&](const std::string& domain, const PConfig& config){
                    if (plain_match(domain, config->deletions)) {
                        to_write = false;
                        to_delete.insert(dns->getDnsHeader()->transactionID);
                        return true;
                    }
                    return false;
                };
                auto get_hashed_domain = [&](const std::string& domain, const PConfig& config){
                    std::string hashed;
                    if (map.isMember(domain))
                        hashed = map[domain].asString();
                    else
                        hashed = replace_domain(domain, config->replacements, config);
                    return hashed;
                };
                auto set_domain = [&](pcpp::IDnsResource* answer, size_t offset){
                    std::string hashed;
                    char tmp[256];
                    auto len = pcpp::DnsLayerExposer::decodeName(*answer,buffer.get(), (const char*)(buffer.get() + offset), tmp);
                    std::string domain((const char*)tmp);
                    if(config->to_lowercase)
                        std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
                    if (delete_if_match(domain, config))
                        return -1L;
                    if(plain_match(domain, config->constants))
                        hashed = domain;
                    else
                        hashed = get_hashed_domain(domain, config);
                    write_domain(dns->getData(), dns->getDataLen(), dns->getData()+offset, hashed);
                    map[domain] = hashed;
                    return (long)len;
                };
                auto process_resource = [&](const std::vector<pcpp::IDnsResource*>& v) {
                    auto is_query = [](pcpp::IDnsResource* p){
                        return dynamic_cast<pcpp::DnsQuery*>(p) != nullptr;
                    };
                    auto has_data = [](pcpp::IDnsResource* p){
                        return dynamic_cast<pcpp::DnsResource*>(p) != nullptr;
                    };
                    for(auto& answer : v) {
                        auto type = answer->getDnsType();
                        auto name_offset = pcpp::DnsLayerExposer::getOffsetInLayer(*answer);
                        auto data_offset = pcpp::DnsLayerExposer::getOffsetInLayer(*answer)
                                           + pcpp::DnsLayerExposer::getNameFieldLength(*answer)
                                           +3*sizeof(uint16_t) + sizeof(uint32_t);
                        switch (type) {
                            case pcpp::DnsType::DNS_TYPE_RRSIG:{
                                auto signer_name_offset = data_offset + 2*sizeof(u_int16_t) + 2*sizeof(u_int8_t) + 3*sizeof(u_int32_t);
                                set_domain(answer, signer_name_offset);
                                set_domain(answer, name_offset);
                                break;
                            }
                            case pcpp::DnsType::DNS_TYPE_SOA: {
                                set_domain(answer, name_offset);
                                if(has_data(answer)) {
                                    auto len = (size_t) set_domain(answer, data_offset);
                                    set_domain(answer, data_offset + len);
                                }else
                                    delete_if_match(answer->getName(), config);
                                break;
                            }
                            case pcpp::DnsType::DNS_TYPE_OPT:
                                // we notice it but don't handle it.
                                break;
                            case pcpp::DnsType::DNS_TYPE_NS:
                            case pcpp::DnsType::DNS_TYPE_CNAME:
                                if(has_data(answer))
                                    set_domain(answer, data_offset);
                                else
                                    delete_if_match(answer->getName(), config);
                            default:
                                set_domain(answer, name_offset);
                                break;
                        }
                    }
                    return true;
                };
                // the sequence here is important because of the domain pointers.
                std::vector<pcpp::IDnsResource*> temp_array;
                for(auto answer = dns->getFirstAnswer(); answer != nullptr; answer = dns->getNextAnswer(answer))
                    temp_array.emplace_back(answer);
                for(auto answer = dns->getFirstAuthority(); answer!= nullptr; answer = dns->getNextAuthority(answer))
                    temp_array.emplace_back(answer);
                for(auto answer = dns->getFirstAdditionalRecord(); answer != nullptr; answer = dns->getNextAdditionalRecord(answer))
                    temp_array.emplace_back(answer);
                for (auto query = dns->getFirstQuery(); query != nullptr; query = dns->getNextQuery(query))
                    temp_array.emplace_back(query);
                process_resource(temp_array);
            }
        }
        if(to_write) {
            write_count++;
            writer.writePacket(rpkt);
        }
    }
    fs << map;
    writer.close();
    reader->close();
    fs.close();
    printf("Done! Write %lld packets of %lld packets in %f seconds",
            write_count, count, ((double)clock() - (double)t)/CLOCKS_PER_SEC);
}