#pragma once
#include <string>
#include <cstdint>

// A FlowKey uniquely identifies one conversation
// Same 5 values = same conversation
struct FlowKey {
    std::string srcIP;
    std::string dstIP;
    uint16_t    srcPort;
    uint16_t    dstPort;
    uint8_t     protocol;  // 6=TCP, 17=UDP

    // needed so we can compare two FlowKeys
    bool operator==(const FlowKey& other) const {
        return srcIP    == other.srcIP    &&
               dstIP    == other.dstIP    &&
               srcPort  == other.srcPort  &&
               dstPort  == other.dstPort  &&
               protocol == other.protocol;
    }
};

// needed so we can use FlowKey as a key in unordered_map
// unordered_map needs to know how to hash our key
struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        // combine all 5 fields into one hash number
        size_t h = std::hash<std::string>{}(k.srcIP);
        h ^= std::hash<std::string>{}(k.dstIP)   << 1;
        h ^= std::hash<uint16_t>{}(k.srcPort)     << 2;
        h ^= std::hash<uint16_t>{}(k.dstPort)     << 3;
        h ^= std::hash<uint8_t>{}(k.protocol)     << 4;
        return h;
    }
};
