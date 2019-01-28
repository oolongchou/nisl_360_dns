cmake_minimum_required(VERSION 3.13)
project(IP)

set(CMAKE_CXX_STANDARD 14)

link_directories(/usr/local/lib)
include_directories(/usr/local/include)
add_executable(IPMap IPMap.cpp)
target_link_libraries(IPMap Pcap++)
target_link_libraries(IPMap Packet++)
target_link_libraries(IPMap Common++)
target_link_libraries(IPMap pcap)
target_link_libraries(IPMap jsoncpp)