#include <iostream>
#include <pcap.h>
#include <thread>
#include <atomic>
#include <chrono>
#include "protocol/ProtocolParser.hpp"
#include "flow/FlowTable.hpp"
#include "detection/ThreatDetector.hpp"
#include "storage/AlertLogger.hpp"
#include "storage/JsonExporter.hpp"
#include "ui/Dashboard.hpp"

FlowTable      flowTable;
AlertLogger    logger("alerts.db");
ThreatDetector detector(logger);
Dashboard*     dashboard = nullptr;

std::atomic<uint64_t> packetCount{0};
uint64_t totalPackets = 0;

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

    if (dashboard) {
        // update stats
        dashboard->setPacketCount(packetCount);
        dashboard->setFlowCount(flowTable.size());

        // add this packet to recent list
        std::string proto = (pkt.protocol == 6) ? "TCP" : "UDP";
        std::string src   = pkt.srcIP + ":" +
                            std::to_string(pkt.srcPort);
        std::string dst   = pkt.dstIP + ":" +
                            std::to_string(pkt.dstPort);
        dashboard->addPacket(proto, src, dst);

        // add flow info
        dashboard->addFlow(src, dst, packetCount, "ACTIVE");

        dashboard->render();
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./threat_engine <file.pcap>\n";
        return 1;
    }

    

totalPackets = 100; // fixed estimate for progress bar
char errbuf[PCAP_ERRBUF_SIZE];


    // create dashboard
    dashboard = new Dashboard();
    dashboard->setTotalExpected(totalPackets);

    // alert callback → tell dashboard
    detector.setAlertCallback(
        [](const std::string& type, const std::string& ip) {
            if (dashboard)
                dashboard->addAlert(type, ip);
        }
    );

    // open pcap file
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        delete dashboard;
        std::cerr << "Error: " << errbuf << "\n";
        return 1;
    }

    pcap_loop(handle, -1, onPacket, nullptr);
    pcap_close(handle);

    // final render then wait for keypress
    if (dashboard) {
        dashboard->render();
        dashboard->waitForKeypress();
    }

    // cleanup dashboard — restore terminal
    delete dashboard;
    dashboard = nullptr;

    // print summary to terminal
    flowTable.printSummary();
    logger.printAllAlerts();

    // export JSON
    JsonExporter exporter("alerts.db", "alerts.json");
    exporter.exportAlerts();

    std::cout << "\n=== Done ===\n";
    return 0;
}

