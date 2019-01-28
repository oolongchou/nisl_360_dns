cmake_minimum_required(VERSION 3.13)
project(Checksum)
set(CMAKE_CXX_STANDARD 14)
set(SOURCE_FILES ReChecksum.cpp)

include_directories(../include)
add_executable(Checksum ReChecksum.cpp)
target_link_libraries(Checksum pcap)
