cmake_minimum_required(VERSION 3.16)
project(NetworkThreatEngine VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(PCAP_LIB pcap REQUIRED)


add_executable(threat_engine 
    src/main.cpp
    src/protocol/ProtocolParser.cpp
)

target_include_directories(threat_engine PRIVATE src)
target_link_libraries(threat_engine PRIVATE ${PCAP_LIB})
