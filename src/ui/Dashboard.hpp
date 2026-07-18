#pragma once
#include <ncurses.h>
#include <string>
#include <vector>
#include <cstdint>

// one alert entry to display
struct AlertEntry {
    std::string time;
    std::string type;
    std::string ip;
};

class Dashboard {
public:
    Dashboard();   // initialize ncurses
    ~Dashboard();  // cleanup ncurses

    // update the stats
    void setPacketCount(uint64_t count);
    void setFlowCount(uint64_t count);
    void addAlert(const std::string& type, const std::string& ip);

    // redraw the whole screen
    void render();

private:
    uint64_t packetCount_ = 0;
    uint64_t flowCount_   = 0;
    std::vector<AlertEntry> alerts_;  // recent alerts list
};

