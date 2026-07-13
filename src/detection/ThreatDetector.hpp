#pragma once
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <ctime>
#include "storage/AlertLogger.hpp"


// Everything we track per IP address
struct IPProfile {
    // for port scan detection
    std::unordered_set<uint16_t> portsContacted;  
    // a SET automatically ignores duplicates
    // so this always contains UNIQUE ports only

    // for SYN flood detection
    uint32_t synCount     = 0;  // how many SYNs sent
    uint32_t synAckCount  = 0;  // how many SYN+ACKs received

    // when did we first see this IP
    time_t firstSeen = 0;
};

class ThreatDetector {
public:
    // pass in the logger so we can save alerts
    explicit ThreatDetector(AlertLogger& logger);

    void analyze(const std::string& srcIP,
                 const std::string& dstIP,
                 uint16_t dstPort,
                 bool isSYN,
                 bool isACK);

private:
    AlertLogger& logger_;  // reference to our logger
    std::unordered_map<std::string, IPProfile> profiles_;
    std::unordered_set<std::string> firedAlerts_;

    void checkPortScan(const std::string& ip, const IPProfile& profile);
    void checkSYNFlood(const std::string& ip, const IPProfile& profile);
    void fireAlert(const std::string& type,
                   const std::string& ip,
                   const std::string& detail);
};
