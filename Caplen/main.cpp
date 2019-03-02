#include <iostream>
#include <fstream>
#include <cstdlib>
const char* Usage = \
"Caplen [input] [caplen]\n"
"Simply rewrite the caplen of the input pcap file.\n";

int main(int argc, char** argv) {
    if(argc != 3){
        std::cout << Usage;
        return 0;
    }
    auto path = argv[1];
    auto caplen_s = argv[2];
    auto caplen = (uint32_t)std::atol(caplen_s);
    std::fstream fs(path, std::ios::binary | std::ios::in | std::ios::out);
    if(!fs.good()){
        std::cout << "Open pcap failed.\n";
        return 0;
    }
    fs.seekg(3*sizeof(uint32_t) + 2*sizeof(uint16_t));
    uint32_t origin;
    fs.read((char*)&origin, 4);
    std::cout << "Original caplen: " << origin << "\n";
    fs.seekp(3*sizeof(uint32_t) + 2*sizeof(uint16_t));
    fs.write((char*)&caplen, 4);
    std::cout << "Writing caplen: " << caplen << "\n";
    fs.close();
}