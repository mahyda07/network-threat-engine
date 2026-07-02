#pragma once
#include "FlowKey.hpp"
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <ctime>
#include <string>

// The state of a TCP connection
enum class TCPState {
    SYN_SENT,      // we saw a SYN
    ESTABLISHED,   // we saw SYN+ACK
    CLOSING,       // we saw FIN
    CLOSED         // connection done
};

// Everything we know about one flow/conversation
struct FlowRecord {
    TCPState state        = TCPState::SYN_SENT;
    uint64_t packetCount  = 0;   // how many packets in this flow
    uint64_t byteCount    = 0;   // how many total bytes
    time_t   firstSeen    = 0;   // when did this flow start
    time_t   lastSeen     = 0;   // when did we last see a packet
};

// The actual table — stores all flows
class FlowTable {
public:
    // call this for every packet
    void update(const FlowKey& key, uint32_t bytes,
                bool isSYN, bool isACK, bool isFIN);

    // print summary at the end
    void printSummary() const;

    // how many flows are we tracking
    size_t size() const;

private:
    // unordered_map = hash map, O(1) lookup
    // FlowKeyHash tells it how to hash our key
    std::unordered_map<FlowKey, FlowRecord, FlowKeyHash> table_;

    // mutex = lock, so multiple threads don't corrupt data
    mutable std::mutex mutex_;
};
