#include "detection/ThreatDetector.hpp"
#include <iostream>
#include <iomanip>
#include <ctime>

// called for every single packet
void ThreatDetector::analyze(const std::string& srcIP,
                              const std::string& dstIP,
                              uint16_t dstPort,
                              bool isSYN,
                              bool isACK) {

    // get or create a profile for this source IP
    IPProfile& profile = profiles_[srcIP];

    // set firstSeen on first packet from this IP
    if (profile.firstSeen == 0)
        profile.firstSeen = std::time(nullptr);

    // record which port this IP just talked to
    // unordered_set ignores duplicates automatically
    profile.portsContacted.insert(dstPort);

    // track SYN and SYN+ACK counts
    if (isSYN && !isACK) profile.synCount++;
    if (isSYN &&  isACK) profile.synAckCount++;

    // now run the checks
    checkPortScan(srcIP, profile);
    checkSYNFlood(srcIP, profile);
}

void ThreatDetector::checkPortScan(const std::string& ip,
                                    const IPProfile& profile) {
    // if this IP has contacted 15 or more unique ports
    // it's probably scanning
    if (profile.portsContacted.size() >= 15) {

        // build a unique key so we don't fire same alert twice
        std::string alertKey = "PORTSCAN_" + ip;

        if (firedAlerts_.count(alertKey) == 0) {
            firedAlerts_.insert(alertKey);
            fireAlert("PORT SCAN",
                      ip,
                      "contacted " +
                      std::to_string(profile.portsContacted.size()) +
                      " unique ports");
        }
    }
}

void ThreatDetector::checkSYNFlood(const std::string& ip,
                                    const IPProfile& profile) {
    // if this IP sent 20+ SYNs but got very few SYN+ACKs back
    // it's probably flooding — sending SYNs and not completing handshakes
    if (profile.synCount >= 20 && profile.synAckCount == 0) {

        std::string alertKey = "SYNFLOOD_" + ip;

        if (firedAlerts_.count(alertKey) == 0) {
            firedAlerts_.insert(alertKey);
            fireAlert("SYN FLOOD",
                      ip,
                      std::to_string(profile.synCount) +
                      " SYNs with 0 completed handshakes");
        }
    }
}

void ThreatDetector::fireAlert(const std::string& type,
                                const std::string& ip,
                                const std::string& detail) {
    // get current time
    std::time_t now = std::time(nullptr);
    std::tm* tm     = std::localtime(&now);

    std::cout << "\n";
    std::cout << "🚨 ALERT: " << type << "\n";
    std::cout << "   IP     : " << ip << "\n";
    std::cout << "   Detail : " << detail << "\n";
    std::cout << "   Time   : " << std::put_time(tm, "%H:%M:%S") << "\n";
    std::cout << "\n";
}
