#pragma once
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <ctime>

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
    // call this for every packet
    void analyze(const std::string& srcIP,
                 const std::string& dstIP,
                 uint16_t dstPort,
                 bool isSYN,
                 bool isACK);

private:
    // one profile per source IP
    std::unordered_map<std::string, IPProfile> profiles_;

    // internal detection functions
    void checkPortScan(const std::string& ip, const IPProfile& profile);
    void checkSYNFlood(const std::string& ip, const IPProfile& profile);

    // so we don't spam the same alert 100 times
    std::unordered_set<std::string> firedAlerts_;

    // print a formatted alert
    void fireAlert(const std::string& type,
                   const std::string& ip,
                   const std::string& detail);
};
