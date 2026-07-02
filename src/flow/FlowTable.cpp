#include "flow/FlowTable.hpp"
#include <iostream>
#include <iomanip>

void FlowTable::update(const FlowKey& key, uint32_t bytes,
                       bool isSYN, bool isACK, bool isFIN) {

    // lock the table so no other thread touches it right now
    std::lock_guard<std::mutex> lock(mutex_);

    // find or create the flow record for this key
    // if key doesn't exist, it gets created automatically
    FlowRecord& rec = table_[key];

    // update stats
    rec.packetCount++;
    rec.byteCount += bytes;
    rec.lastSeen   = std::time(nullptr);

    // set firstSeen only on the first packet
    if (rec.packetCount == 1)
        rec.firstSeen = rec.lastSeen;

    // update TCP state machine
    if (isSYN && !isACK) rec.state = TCPState::SYN_SENT;
    else if (isSYN && isACK) rec.state = TCPState::ESTABLISHED;
    else if (isFIN) rec.state = TCPState::CLOSING;
    else if (rec.state == TCPState::CLOSING) rec.state = TCPState::CLOSED;
}

void FlowTable::printSummary() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::cout << "\n=== Flow Table (" << table_.size() << " flows) ===\n";

    for (const auto& [key, rec] : table_) {

        // print addresses
        std::cout << key.srcIP << ":" << key.srcPort
                  << " → "
                  << key.dstIP << ":" << key.dstPort;

        // print protocol
        std::cout << " | " << (key.protocol == 6 ? "TCP" : "UDP");

        // print stats
        std::cout << " | " << rec.packetCount << " pkts"
                  << " | " << rec.byteCount   << " bytes";

        // print TCP state
        if (key.protocol == 6) {
            std::string stateStr;
            switch (rec.state) {
                case TCPState::SYN_SENT:    stateStr = "SYN_SENT";    break;
                case TCPState::ESTABLISHED: stateStr = "ESTABLISHED";  break;
                case TCPState::CLOSING:     stateStr = "CLOSING";      break;
                case TCPState::CLOSED:      stateStr = "CLOSED";       break;
            }
            std::cout << " | " << stateStr;
        }

        std::cout << "\n";
    }
}

size_t FlowTable::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.size();
}
