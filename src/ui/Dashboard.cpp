#include "ui/Dashboard.hpp"
#include <ctime>
#include <sstream>

Dashboard::Dashboard() {
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    start_color();

    init_pair(1, COLOR_GREEN, COLOR_BLACK);
    init_pair(2, COLOR_RED,   COLOR_BLACK);
    init_pair(3, COLOR_CYAN,  COLOR_BLACK);
}

Dashboard::~Dashboard() {
    endwin();
}

void Dashboard::setPacketCount(uint64_t count) {
    packetCount_ = count;
}

void Dashboard::setFlowCount(uint64_t count) {
    flowCount_ = count;
}

void Dashboard::addAlert(const std::string& type,
                          const std::string& ip) {
    std::time_t now = std::time(nullptr);
    char timebuf[16];
    std::strftime(timebuf, sizeof(timebuf),
                  "%H:%M:%S", std::localtime(&now));

    AlertEntry entry;
    entry.time = timebuf;
    entry.type = type;
    entry.ip   = ip;

    alerts_.push_back(entry);

    if (alerts_.size() > 5)
        alerts_.erase(alerts_.begin());
}

void Dashboard::render() {
    clear();

    int row = 0;

    // title
    attron(COLOR_PAIR(3) | A_BOLD);
    mvprintw(row++, 0, "+========================================+");
    mvprintw(row++, 0, "|   Network Threat Engine - Live View   |");
    mvprintw(row++, 0, "+========================================+");
    attroff(COLOR_PAIR(3) | A_BOLD);

    // stats
    attron(COLOR_PAIR(1));
    mvprintw(row++, 0, "|  Packets captured : %-18lu  |", packetCount_);
    mvprintw(row++, 0, "|  Active flows     : %-18lu  |", flowCount_);
    mvprintw(row++, 0, "|  Alerts fired     : %-18zu  |", alerts_.size());
    attroff(COLOR_PAIR(1));

    // alerts header
    attron(COLOR_PAIR(3) | A_BOLD);
    mvprintw(row++, 0, "+========================================+");
    mvprintw(row++, 0, "|  RECENT ALERTS                         |");
    mvprintw(row++, 0, "+========================================+");
    attroff(COLOR_PAIR(3) | A_BOLD);

    // alert entries
    if (alerts_.empty()) {
        attron(COLOR_PAIR(1));
        mvprintw(row++, 0, "|  No alerts yet...                      |");
        attroff(COLOR_PAIR(1));
    } else {
        for (const auto& alert : alerts_) {
            attron(COLOR_PAIR(2) | A_BOLD);
            mvprintw(row++, 0,
                "|  [%s] %-8s from %-14s  |",
                alert.time.c_str(),
                alert.type.c_str(),
                alert.ip.c_str());
            attroff(COLOR_PAIR(2) | A_BOLD);
        }
    }

    // footer
    attron(COLOR_PAIR(3) | A_BOLD);
    mvprintw(row++, 0, "+========================================+");
    mvprintw(row++, 0, "  Press Ctrl+C to stop");
    attroff(COLOR_PAIR(3) | A_BOLD);

    refresh();
}
