#include <iostream>
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
