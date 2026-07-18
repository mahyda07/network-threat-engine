#include "ui/Dashboard.hpp"
#include <ctime>
#include <string>
#include <algorithm>

#define WIDTH 52

Dashboard::Dashboard() {
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    start_color();
    keypad(stdscr, TRUE);

    init_pair(1, COLOR_GREEN,   COLOR_BLACK);
    init_pair(2, COLOR_RED,     COLOR_BLACK);
    init_pair(3, COLOR_CYAN,    COLOR_BLACK);
    init_pair(4, COLOR_YELLOW,  COLOR_BLACK);
    init_pair(5, COLOR_MAGENTA, COLOR_BLACK);
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

void Dashboard::setTotalExpected(uint64_t total) {
    totalExpected_ = total > 0 ? total : 1;
}

void Dashboard::addAlert(const std::string& type,
                          const std::string& ip) {
    std::time_t now = std::time(nullptr);
    char timebuf[16];
    std::strftime(timebuf, sizeof(timebuf),
                  "%H:%M:%S", std::localtime(&now));
    AlertEntry e;
    e.time = timebuf;
    e.type = type;
    e.ip   = ip;
    alerts_.push_back(e);
    if (alerts_.size() > 3)
        alerts_.erase(alerts_.begin());
}

void Dashboard::addPacket(const std::string& proto,
                           const std::string& src,
                           const std::string& dst) {
    PacketEntry e;
    e.proto = proto;
    e.src   = src;
    e.dst   = dst;
    recentPackets_.push_back(e);
    if (recentPackets_.size() > 4)
        recentPackets_.erase(recentPackets_.begin());
}

void Dashboard::addFlow(const std::string& src,
                         const std::string& dst,
                         uint64_t packets,
                         const std::string& state) {
    for (auto& f : flows_) {
        if (f.src == src && f.dst == dst) {
            f.packets = packets;
            f.state   = state;
            return;
        }
    }
    FlowEntry e;
    e.src     = src;
    e.dst     = dst;
    e.packets = packets;
    e.state   = state;
    flows_.push_back(e);
    if (flows_.size() > 4)
        flows_.erase(flows_.begin());
}

// prints a full-width separator line
static void topBar(int row) {
    mvprintw(row, 0, "+");
    for (int i = 0; i < WIDTH - 2; i++) printw("=");
    printw("+");
}

static void midBar(int row) {
    mvprintw(row, 0, "+");
    for (int i = 0; i < WIDTH - 2; i++) printw("-");
    printw("+");
}

// prints one content row — content must be exactly WIDTH-4 chars
static void row_line(int row, int pair, const std::string& content) {
    // pad or trim to exactly WIDTH-4
    std::string s = content;
    int inner = WIDTH - 4;
    if ((int)s.size() < inner)
        s += std::string(inner - s.size(), ' ');
    else if ((int)s.size() > inner)
        s = s.substr(0, inner);

    attron(COLOR_PAIR(pair));
    mvprintw(row, 0, "| %s |", s.c_str());
    attroff(COLOR_PAIR(pair));
}

void Dashboard::render() {
    clear();
    int row = 0;
    int inner = WIDTH - 4;  // usable chars between "| " and " |"

    // ── Title ──
    attron(COLOR_PAIR(3) | A_BOLD);
    topBar(row++);
    row_line(row++, 3, " Network Threat Engine - Live View");
    topBar(row++);
    attroff(COLOR_PAIR(3) | A_BOLD);

    // ── Stats ──
    {
        char buf[64];
        snprintf(buf, sizeof(buf),
                 "Packets : %-6lu   Flows : %-6lu",
                 packetCount_, flowCount_);
        row_line(row++, 1, std::string(buf));
    }

    // ── Progress bar ──
    {
        int barW   = inner - 8;  // space for "[", "]", " NNN%"
        int filled = (int)((packetCount_ * barW) /
                     (totalExpected_ > 0 ? totalExpected_ : 1));
        filled = std::min(filled, barW);
        int pct = (int)((packetCount_ * 100) /
                  (totalExpected_ > 0 ? totalExpected_ : 1));
        pct = std::min(pct, 100);

        std::string bar = "[";
        for (int i = 0; i < barW; i++)
            bar += (i < filled ? '=' : ' ');
        bar += "] ";
        char pctbuf[8];
        snprintf(pctbuf, sizeof(pctbuf), "%3d%%", pct);
        bar += pctbuf;

        row_line(row++, 1, bar);
    }

    // ── Recent Packets ──
    attron(COLOR_PAIR(3) | A_BOLD);
    topBar(row++);
    row_line(row++, 3, " RECENT PACKETS");
    midBar(row++);
    attroff(COLOR_PAIR(3) | A_BOLD);

    if (recentPackets_.empty()) {
        row_line(row++, 4, " Waiting for packets...");
    } else {
        for (const auto& p : recentPackets_) {
            std::string line = " " + p.proto + " " +
                               p.src + " -> " + p.dst;
            row_line(row++, 4, line);
        }
    }

    // ── Active Flows ──
    attron(COLOR_PAIR(3) | A_BOLD);
    topBar(row++);
    row_line(row++, 3, " ACTIVE FLOWS");
    midBar(row++);
    attroff(COLOR_PAIR(3) | A_BOLD);

    if (flows_.empty()) {
        row_line(row++, 5, " No flows yet...");
    } else {
        for (const auto& f : flows_) {
            std::string line = " " + f.src + "->" +
                               f.dst + " " +
                               std::to_string(f.packets) + "p";
            row_line(row++, 5, line);
        }
    }

    // ── Alerts ──
    attron(COLOR_PAIR(3) | A_BOLD);
    topBar(row++);
    row_line(row++, 3, " ALERTS");
    midBar(row++);
    attroff(COLOR_PAIR(3) | A_BOLD);

    if (alerts_.empty()) {
        row_line(row++, 1, " No alerts yet...");
    } else {
        for (const auto& a : alerts_) {
            std::string line = " [" + a.time + "] " +
                               a.type + " from " + a.ip;
            attron(COLOR_PAIR(2) | A_BOLD);
            row_line(row, 2, line);
            attroff(COLOR_PAIR(2) | A_BOLD);
            row++;
        }
    }

    // ── Footer ──
    attron(COLOR_PAIR(3) | A_BOLD);
    topBar(row++);
    row_line(row++, 3, " Press any key to exit");
    topBar(row++);
    attroff(COLOR_PAIR(3) | A_BOLD);

    refresh();
}

void Dashboard::waitForKeypress() {
    nodelay(stdscr, FALSE);
    timeout(-1);
    flushinp();
    getch();
}
