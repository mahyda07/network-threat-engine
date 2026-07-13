#pragma once
#include <string>
#include <sqlite3.h>

class AlertLogger {
public:
    // open (or create) the database file
    explicit AlertLogger(const std::string& dbPath);
    
    // close database on destruction
    ~AlertLogger();

    // save one alert to the database
    void logAlert(const std::string& type,
                  const std::string& ip,
                  const std::string& detail);

    // print all saved alerts from database
    void printAllAlerts();

private:
    sqlite3* db_ = nullptr;

    // creates the alerts table if it doesn't exist
    void createTable();
};
