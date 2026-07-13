#include "detection/ThreatDetector.hpp"
#include <iostream>
#include <iomanip>
#include <ctime>

// constructor — store reference to logger
ThreatDetector::ThreatDetector(AlertLogger& logger) 
    : logger_(logger) {}

void ThreatDetector::analyze(const std::string& srcIP,
                              const std::string& dstIP,
                              uint16_t dstPort,
                              bool isSYN,
                              bool isACK) {
    IPProfile& profile = profiles_[srcIP];

    if (profile.firstSeen == 0)
        profile.firstSeen = std::time(nullptr);

    profile.portsContacted.insert(dstPort);

    if (isSYN && !isACK) profile.synCount++;
    if (isSYN &&  isACK) profile.synAckCount++;

    checkPortScan(srcIP, profile);
    checkSYNFlood(srcIP, profile);
}

void ThreatDetector::checkPortScan(const std::string& ip,
                                    const IPProfile& profile) {
    if (profile.portsContacted.size() >= 15) {
        std::string alertKey = "PORTSCAN_" + ip;
        if (firedAlerts_.count(alertKey) == 0) {
            firedAlerts_.insert(alertKey);
            std::string detail = "contacted " +
                std::to_string(profile.portsContacted.size()) +
                " unique ports";
            fireAlert("PORT SCAN", ip, detail);
        }
    }
}

void ThreatDetector::checkSYNFlood(const std::string& ip,
                                    const IPProfile& profile) {
    if (profile.synCount >= 20 && profile.synAckCount == 0) {
        std::string alertKey = "SYNFLOOD_" + ip;
        if (firedAlerts_.count(alertKey) == 0) {
            firedAlerts_.insert(alertKey);
            std::string detail = std::to_string(profile.synCount) +
                " SYNs with 0 completed handshakes";
            fireAlert("SYN FLOOD", ip, detail);
        }
    }
}

void ThreatDetector::fireAlert(const std::string& type,
                                const std::string& ip,
                                const std::string& detail) {
    std::time_t now = std::time(nullptr);
    std::tm* tm     = std::localtime(&now);

    // print to screen as before
    std::cout << "\n";
    std::cout << "🚨 ALERT: " << type << "\n";
    std::cout << "   IP     : " << ip << "\n";
    std::cout << "   Detail : " << detail << "\n";
    std::cout << "   Time   : " 
              << std::put_time(tm, "%H:%M:%S") << "\n\n";

    // AND save to database
    logger_.logAlert(type, ip, detail);
}

