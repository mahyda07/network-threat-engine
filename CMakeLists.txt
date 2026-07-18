cmake_minimum_required(VERSION 3.16)
project(NetworkThreatEngine VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(PCAP_LIB   pcap    REQUIRED)
find_library(SQLITE_LIB sqlite3 REQUIRED)
find_library(NCURSES_LIB ncurses REQUIRED)

add_executable(threat_engine
    src/main.cpp
    src/protocol/ProtocolParser.cpp
    src/flow/FlowTable.cpp
    src/detection/ThreatDetector.cpp
    src/storage/AlertLogger.cpp
    src/ui/Dashboard.cpp
)

target_include_directories(threat_engine PRIVATE src)
target_link_libraries(threat_engine PRIVATE
    ${PCAP_LIB}
    ${SQLITE_LIB}
    ${NCURSES_LIB}
)
