#pragma once
#include <cstdint>
#include <string>

// Ethernet header is always exactly 14 bytes
struct EthernetHeader {
    uint8_t  dst[6];      // destination MAC (6 bytes)
    uint8_t  src[6];      // source MAC (6 bytes)
    uint16_t ethertype;   // 0x0800=IP, 0x0806=ARP
};

// IP header is minimum 20 bytes
struct IPHeader {
    uint8_t  versionIHL;    // version + header length packed in 1 byte
    uint8_t  tos;           // type of service (we ignore this)
    uint16_t totalLength;   // total packet length
    uint16_t id;            // identification (we ignore this)
    uint16_t flagsFragment; // flags (we ignore this)
    uint8_t  ttl;           // time to live (we ignore this)
    uint8_t  protocol;      // 6=TCP, 17=UDP  ← we care about this
    uint16_t checksum;      // checksum (we ignore this)
    uint32_t srcIP;         // source IP address ← we care about this
    uint32_t dstIP;         // destination IP address ← we care about this

    // helper: how long is this IP header in bytes?
    int headerLen() const { return (versionIHL & 0x0F) * 4; }
};

// This is what our parser hands back after reading a packet
struct ParsedPacket {
    bool        valid    = false;  // did we successfully parse it?
    std::string srcIP;             // source IP as text
    std::string dstIP;             // destination IP as text
    uint16_t    srcPort  = 0;      // source port
    uint16_t    dstPort  = 0;      // destination port
    uint8_t     protocol = 0;      // 6=TCP, 17=UDP
    bool        isSYN    = false;  // TCP SYN flag
    bool        isACK    = false;  // TCP ACK flag
    bool        isFIN    = false;  // TCP FIN flag
};

// This is the function we'll call for every packet
ParsedPacket parsePacket(const uint8_t* data, uint32_t len);
