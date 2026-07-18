#include <iostream>
#include <pcap.h>
#include <thread>
#include <atomic>
#include <chrono>
#include "protocol/ProtocolParser.hpp"
#include "flow/FlowTable.hpp"
#include "detection/ThreatDetector.hpp"
#include "storage/AlertLogger.hpp"
#include "ui/Dashboard.hpp"

// global state
FlowTable      flowTable;
AlertLogger    logger("alerts.db");
ThreatDetector detector(logger);
Dashboard*     dashboard = nullptr;

// packet counter
std::atomic<uint64_t> packetCount{0};

void onPacket(uint8_t* user,
              const struct pcap_pkthdr* header,
              const uint8_t* data) {

    ParsedPacket pkt = parsePacket(data, header->len);
    if (!pkt.valid) return;

    FlowKey key;
    key.srcIP    = pkt.srcIP;
    key.dstIP    = pkt.dstIP;
    key.srcPort  = pkt.srcPort;
    key.dstPort  = pkt.dstPort;
    key.protocol = pkt.protocol;
    flowTable.update(key, header->len,
                     pkt.isSYN, pkt.isACK, pkt.isFIN);

    detector.analyze(pkt.srcIP, pkt.dstIP,
                     pkt.dstPort,
                     pkt.isSYN, pkt.isACK);

    packetCount++;

    // update dashboard every packet
    if (dashboard) {
        dashboard->setPacketCount(packetCount);
        dashboard->setFlowCount(flowTable.size());
        dashboard->render();
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./threat_engine <file.pcap>\n";
        return 1;
    }

    // create dashboard
    dashboard = new Dashboard();

    // when alert fires → tell dashboard
    detector.setAlertCallback(
        [](const std::string& type, const std::string& ip) {
            if (dashboard)
                dashboard->addAlert(type, ip);
        }
    );

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        delete dashboard;
        std::cerr << "Error: " << errbuf << "\n";
        return 1;
    }

    pcap_loop(handle, -1, onPacket, nullptr);

    // final render
    if (dashboard) dashboard->render();

    // wait 3 seconds so user can see final state
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // cleanup
    delete dashboard;
    dashboard = nullptr;

    // back to normal terminal — print summary
    flowTable.printSummary();
    logger.printAllAlerts();

    std::cout << "\n=== Done ===\n";
    pcap_close(handle);
    return 0;
}
