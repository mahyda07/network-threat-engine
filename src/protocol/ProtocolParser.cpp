#include "protocol/ProtocolParser.hpp"
#include <arpa/inet.h>    // for ntohs(), ntohl(), inet_ntoa()
#include <netinet/in.h>   // for struct in_addr


ParsedPacket parsePacket(const uint8_t* data, uint32_t len) {
    ParsedPacket result;  // starts with valid=false

    // Step 1: need at least 14 bytes for ethernet header
    if (len < 14) return result;

    // Step 2: read ethernet header
    // reinterpret_cast says "treat these bytes as an EthernetHeader struct"
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(data);

    // Step 3: check if it's an IP packet (ethertype == 0x0800)
    // ntohs fixes byte order (network→host)
    if (ntohs(eth->ethertype) != 0x0800) return result;

    // Step 4: need at least 14+20 bytes for IP header
    if (len < 34) return result;

    // Step 5: read IP header — starts at byte 14
    const IPHeader* ip = reinterpret_cast<const IPHeader*>(data + 14);

    // Step 6: convert IPs from raw bytes to readable text like "192.168.1.1"
    struct in_addr srcAddr, dstAddr;
    srcAddr.s_addr = ip->srcIP;
    dstAddr.s_addr = ip->dstIP;
    result.srcIP   = inet_ntoa(srcAddr);
    result.dstIP   = inet_ntoa(dstAddr);
    result.protocol = ip->protocol;

    // Step 7: figure out where TCP/UDP starts
    // it starts right after the IP header ends
    int ipHeaderLen       = ip->headerLen();
    uint32_t tcpUdpOffset = 14 + ipHeaderLen;

    // Step 8: handle TCP (protocol == 6)
    if (ip->protocol == 6) {
        if (len < tcpUdpOffset + 20) return result;

        // TCP header starts at tcpUdpOffset
        // bytes 0-1 of TCP = source port
        // bytes 2-3 of TCP = destination port
        // byte 13 of TCP   = flags
        const uint8_t* tcp = data + tcpUdpOffset;

        // read ports — need ntohs because network byte order
        result.srcPort = ntohs(*reinterpret_cast<const uint16_t*>(tcp));
        result.dstPort = ntohs(*reinterpret_cast<const uint16_t*>(tcp + 2));

        // read flags byte (byte 13 of TCP header)
        uint8_t flags  = tcp[13];
        result.isSYN   = (flags & 0x02);  // bit 1 = SYN
        result.isACK   = (flags & 0x10);  // bit 4 = ACK
        result.isFIN   = (flags & 0x01);  // bit 0 = FIN
    }

    // Step 9: handle UDP (protocol == 17)
    else if (ip->protocol == 17) {
        if (len < tcpUdpOffset + 8) return result;

        const uint8_t* udp = data + tcpUdpOffset;
        result.srcPort = ntohs(*reinterpret_cast<const uint16_t*>(udp));
        result.dstPort = ntohs(*reinterpret_cast<const uint16_t*>(udp + 2));
    }

    else {
        // not TCP or UDP — we don't handle it
        return result;
    }

    // if we got here, parsing succeeded
    result.valid = true;
    return result;
}
