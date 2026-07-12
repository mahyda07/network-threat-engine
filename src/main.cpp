#include <iostream>
#include <pcap.h>
#include "protocol/ProtocolParser.hpp"
#include "flow/FlowTable.hpp"
#include "detection/ThreatDetector.hpp"

FlowTable     flowTable;
ThreatDetector detector;

void onPacket(uint8_t* user,
              const struct pcap_pkthdr* header,
              const uint8_t* data) {

    ParsedPacket pkt = parsePacket(data, header->len);
    if (!pkt.valid) return;

    // update flow table
    FlowKey key;
    key.srcIP    = pkt.srcIP;
    key.dstIP    = pkt.dstIP;
    key.srcPort  = pkt.srcPort;
    key.dstPort  = pkt.dstPort;
    key.protocol = pkt.protocol;
    flowTable.update(key, header->len,
                     pkt.isSYN, pkt.isACK, pkt.isFIN);

    // run threat detection on every packet
    detector.analyze(pkt.srcIP, pkt.dstIP,
                     pkt.dstPort,
                     pkt.isSYN, pkt.isACK);

    // print packet
    std::string proto = (pkt.protocol == 6) ? "TCP" : "UDP";
    std::cout << "[" << proto << "] "
              << pkt.srcIP << ":" << pkt.srcPort
              << " -> "
              << pkt.dstIP << ":" << pkt.dstPort
              << " | " << header->len << " bytes\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./threat_engine <file.pcap>\n";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        std::cerr << "Error: " << errbuf << "\n";
        return 1;
    }

    std::cout << "=== Network Threat Engine ===\n\n";
    pcap_loop(handle, -1, onPacket, nullptr);
    flowTable.printSummary();
    std::cout << "\n=== Done ===\n";

    pcap_close(handle);
    return 0;
}

