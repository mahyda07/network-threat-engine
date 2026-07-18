#pragma once
#include <ncurses.h>
#include <string>
#include <vector>
#include <cstdint>

struct AlertEntry {
    std::string time;
    std::string type;
    std::string ip;
};

struct PacketEntry {
    std::string proto;
    std::string src;
    std::string dst;
};

struct FlowEntry {
    std::string src;
    std::string dst;
    uint64_t    packets;
    std::string state;
};

class Dashboard {
public:
    Dashboard();
    ~Dashboard();

    void setPacketCount(uint64_t count);
    void setFlowCount(uint64_t count);
    void setTotalExpected(uint64_t total);
    void addAlert(const std::string& type, const std::string& ip);
    void addPacket(const std::string& proto,
                   const std::string& src,
                   const std::string& dst);
    void addFlow(const std::string& src,
                 const std::string& dst,
                 uint64_t packets,
                 const std::string& state);

    void render();

    // wait until user presses a key
    void waitForKeypress();

private:
    uint64_t packetCount_   = 0;
    uint64_t flowCount_     = 0;
    uint64_t totalExpected_ = 100;

    std::vector<AlertEntry>  alerts_;
    std::vector<PacketEntry> recentPackets_;
    std::vector<FlowEntry>   flows_;

    void drawBox(int row, const std::string& label);
    void drawProgressBar(int row, uint64_t current, uint64_t total);
};
