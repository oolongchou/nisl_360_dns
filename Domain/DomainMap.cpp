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
#include<DnsLayer.h>
#include<json/json.h>
#include<PcapFileDevice.h>
#ifdef _HASH_SHA1
#include<openssl/sha.h>
static const size_t digest_len = SHA_DIGEST_LENGTH;
#else
#include<openssl/md5.h>
static const size_t digest_len = MD5_DIGEST_LENGTH;
#endif

typedef struct _config{
    bool to_lowercase;
    std::vector<std::string> deletions;
    std::vector<std::string> constants;
    std::map<std::string, std::string> replacements;
} Config;

typedef std::shared_ptr<unsigned char> Digest;

typedef std::shared_ptr<Config> PConfig;

bool lhsEndsWithrhs(const std::string& lhs, const std::string& rhs){
    if(lhs.length() < rhs.length())
        return false;
    return lhs.compare(lhs.length() - rhs.length(), rhs.length(), rhs) == 0;
}

Digest hash(const char* str, u_int64_t len){
    auto buffer = new unsigned char[digest_len];
#ifdef _HASH_SHA1
    SHA1((const unsigned char*)str, len, buffer);
#else
    MD5((const unsigned char*)str, len, buffer);
#endif
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

std::string replace_domain(const std::string &domain, const std::map<std::string, std::string> &replacements){
    std::string result;
    std::string new_suffix;
    bool to_replace = false;
    for(auto& it : replacements) {
        std::string suffix = it.first;
        if (lhsEndsWithrhs(domain, suffix)) {
            result = domain.substr(0, domain.length() - suffix.length());
            new_suffix = it.second;
            to_replace = true;
        } else
            result = domain;
    }
    size_t last_pos = 0;
    for(size_t i = 0; i<=result.length();i++){
        if((i == result.length()&&last_pos != i) || (i<result.length() && result[i] == '.')){
            size_t subdomain_len = i - last_pos;
            std::string digest_hex =
                    format_digest(hash(domain.substr(last_pos, subdomain_len).c_str(), subdomain_len), subdomain_len/2 + 1);
            for(size_t j = 0; j<subdomain_len;j++)
                result[last_pos + j] = digest_hex[j];
            last_pos = i + 1;
        }
    }
    if(to_replace)
        return result + new_suffix;
    else
        return result;
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
        if(dns != nullptr){
            u_int16_t tid = dns->getDnsHeader()->transactionID;
            if(to_delete.count(tid) == 1){
                to_delete.erase(tid);
                to_write = false;
            }else {
                // not elegant at all. :(
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
                        hashed = replace_domain(domain, config->replacements);
                    return hashed;
                };
                auto process_domain = [&](std::string& domain, const PConfig& config, std::string& hashed){
                    if(config->to_lowercase)
                        std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
                    if (delete_if_match(domain, config))
                        return false;
                    if(plain_match(domain, config->constants)) {
                        hashed = domain;
                        return true;
                    }
                    hashed = get_hashed_domain(domain, config);
                    return true;
                };
                for (auto query = dns->getFirstQuery(); query != nullptr; query = dns->getNextQuery(query)) {
                    auto domain = query->getName();
                    std::string hashed;
                    if(process_domain(domain, config, hashed)) {
                        map[domain] = hashed;
                        query->setName(hashed);
                    }
                }
                for(auto answer = dns->getFirstAnswer(); answer != nullptr; answer = dns->getNextAnswer(answer)) {
                    auto domain = answer->getName();
                    auto type = answer->getDnsType();
                    switch (type) {
                        case pcpp::DnsType::DNS_TYPE_CNAME: {
                            auto cname = answer->getDataAsString();
                            std::string hashed;
                            if (process_domain(cname, config, hashed)) {
                                map[domain] = hashed;
                                answer->setData(hashed);
                            }
                        }
                            break;
                        case pcpp::DnsType::DNS_TYPE_NSEC:
                        case pcpp::DnsType::DNS_TYPE_NSEC3:
                        case pcpp::DnsType::DNS_TYPE_NSEC3PARAM:
                        case pcpp::DnsType::DNS_TYPE_RRSIG: {
                            // Since no one know the private key, so it's
                            // okay to leave it as it is.
                            auto dnssec = answer->getDataAsString();
                            printf("%lld packet finds DNSSEC:%s\n", count, dnssec.c_str());
                            break;
                        }
                        case pcpp::DnsType::DNS_TYPE_A:
                        case pcpp::DnsType::DNS_TYPE_AAAA:
                            // ignore normal ipv4 and ipv6 response.
                            break;
                        case pcpp::DNS_TYPE_NS:
                            // not implemented.
                            break;
                        default:
                            printf("the answer of %lld packet with type id %d isn't processed.\n", count, type);
                    }
                }
                // now we should go to authoritative servers and additional records.
                // to be implemented.
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