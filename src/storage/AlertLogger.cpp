#include "storage/AlertLogger.hpp"
#include <iostream>
#include <ctime>
#include <stdexcept>

AlertLogger::AlertLogger(const std::string& dbPath) {
    // open the database file
    // if file doesn't exist, sqlite creates it automatically
    int rc = sqlite3_open(dbPath.c_str(), &db_);
    
    if (rc != SQLITE_OK) {
        throw std::runtime_error("Cannot open database: " +
                                 std::string(sqlite3_errmsg(db_)));
    }

    std::cout << "[DB] Alert database opened: " << dbPath << "\n";
    createTable();
}

AlertLogger::~AlertLogger() {
    if (db_) sqlite3_close(db_);
}

void AlertLogger::createTable() {
    // SQL to create our alerts table
    // IF NOT EXISTS means it's safe to run every time
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            type      TEXT NOT NULL,
            ip        TEXT NOT NULL,
            detail    TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
    )";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errMsg);

    if (rc != SQLITE_OK) {
        std::string err = errMsg;
        sqlite3_free(errMsg);
        throw std::runtime_error("Table creation failed: " + err);
    }

    std::cout << "[DB] Alerts table ready\n";
}

void AlertLogger::logAlert(const std::string& type,
                            const std::string& ip,
                            const std::string& detail) {
    // get current timestamp as string
    std::time_t now = std::time(nullptr);
    char timebuf[32];
    std::strftime(timebuf, sizeof(timebuf),
                  "%Y-%m-%d %H:%M:%S",
                  std::localtime(&now));

    // SQL INSERT statement
    // ? marks are placeholders — we fill them in safely below
    const char* sql = 
        "INSERT INTO alerts (type, ip, detail, timestamp) "
        "VALUES (?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;

    // prepare the statement
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    // bind values to the ? placeholders
    // 1, 2, 3, 4 = position of each ?
    sqlite3_bind_text(stmt, 1, type.c_str(),   -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ip.c_str(),     -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, detail.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, timebuf,        -1, SQLITE_STATIC);

    // execute the insert
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    std::cout << "[DB] Alert saved: " << type << " from " << ip << "\n";
}

void AlertLogger::printAllAlerts() {
    const char* sql = 
        "SELECT id, type, ip, detail, timestamp "
        "FROM alerts ORDER BY id;";

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    std::cout << "\n=== Saved Alerts from Database ===\n";

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // read each column
        int         id        = sqlite3_column_int (stmt, 0);
        const char* type      = (const char*)sqlite3_column_text(stmt, 1);
        const char* ip        = (const char*)sqlite3_column_text(stmt, 2);
        const char* detail    = (const char*)sqlite3_column_text(stmt, 3);
        const char* timestamp = (const char*)sqlite3_column_text(stmt, 4);

        std::cout << "[" << id << "] "
                  << timestamp << " | "
                  << type      << " | "
                  << ip        << " | "
                  << detail    << "\n";
    }

    sqlite3_finalize(stmt);
}
