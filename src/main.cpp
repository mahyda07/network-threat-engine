/*/#include <iostream>
#include <pcap.h>
#include <ctime>
#include <iomanip>

void onPacket(uint8_t* user, const struct pcap_pkthdr* header, const uint8_t* data) {

    std::time_t t = header->ts.tv_sec;
    std::tm* tm = std::localtime(&t);

    std::cout << "--- Packet ---\n";
    std::cout << "Time   : " << std::put_time(tm, "%H:%M:%S") << "\n";
    std::cout << "Length : " << header->len << " bytes\n";

    std::cout << "Hex    : ";
    for (int i = 0; i < 16 && i < (int)header->len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)data[i] << " ";
    }
    std::cout << std::dec << "\n\n";
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cerr << "Usage: ./threat_engine <file.pcap>\n";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);

    if (handle == nullptr) {
        std::cerr << "Error opening file: " << errbuf << "\n";
        return 1;
    }

    std::cout << "=== Reading: " << argv[1] << " ===\n\n";
    pcap_loop(handle, -1, onPacket, nullptr);
    std::cout << "=== Done ===\n";

    pcap_close(handle);
    return 0;
}

/*/












#include <iostream>
#include <pcap.h>
#include "protocol/ProtocolParser.hpp"

void onPacket(uint8_t* user, const struct pcap_pkthdr* header, const uint8_t* data) {

    // parse this raw packet
    ParsedPacket pkt = parsePacket(data, header->len);

    // if parsing failed (not IP, or too short) skip it
    if (!pkt.valid) {
        std::cout << "[UNKNOWN] non-IP packet, skipping\n";
        return;
    }

    // print protocol
    std::string proto = (pkt.protocol == 6) ? "TCP" : "UDP";
    std::cout << "[" << proto << "] ";

    // print source and destination
    std::cout << pkt.srcIP << ":" << pkt.srcPort
              << " → "
              << pkt.dstIP << ":" << pkt.dstPort;

    // print packet size
    std::cout << " | " << header->len << " bytes";

    // if TCP, print which flags are set
    if (pkt.protocol == 6) {
        std::cout << " | flags: ";
        if (pkt.isSYN) std::cout << "SYN ";
        if (pkt.isACK) std::cout << "ACK ";
        if (pkt.isFIN) std::cout << "FIN ";
    }

    std::cout << "\n";
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
    std::cout << "\n=== Done ===\n";

    pcap_close(handle);
    return 0;
}
