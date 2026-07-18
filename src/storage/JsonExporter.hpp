#pragma once
#include <string>
#include "AlertLogger.hpp"

class JsonExporter {
public:
    // pass the database path and output file path
    JsonExporter(const std::string& dbPath,
                 const std::string& outputPath);

    // read alerts from db and write to json file
    void exportAlerts();

private:
    std::string dbPath_;
    std::string outputPath_;
};
