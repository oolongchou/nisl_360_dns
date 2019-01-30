cmake_minimum_required(VERSION 3.13)
project(MacMap)

set(CMAKE_CXX_STANDARD 14)

link_directories(/usr/local/lib)
include_directories(/usr/local/include)
include_directories(/usr/local/include/pcapplusplus)
add_executable(MACMap MACMap.cpp)
target_link_libraries(MACMap Pcap++)
target_link_libraries(MACMap Packet++)
target_link_libraries(MACMap Common++)
target_link_libraries(MACMap pcap)
target_link_libraries(MACMap jsoncpp)