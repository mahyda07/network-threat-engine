#include "storage/JsonExporter.hpp"
#include <sqlite3.h>
#include <fstream>
#include <iostream>
#include <vector>

// simple struct to hold one alert row
struct AlertRow {
    int         id;
    std::string type;
    std::string ip;
    std::string detail;
    std::string timestamp;
};

JsonExporter::JsonExporter(const std::string& dbPath,
                            const std::string& outputPath)
    : dbPath_(dbPath), outputPath_(outputPath) {}

void JsonExporter::exportAlerts() {

    // open the database
    sqlite3* db = nullptr;
    sqlite3_open(dbPath_.c_str(), &db);

    // read all alerts
    const char* sql =
        "SELECT id, type, ip, detail, timestamp "
        "FROM alerts ORDER BY id;";

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    std::vector<AlertRow> rows;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AlertRow row;
        row.id        = sqlite3_column_int(stmt, 0);
        row.type      = (const char*)sqlite3_column_text(stmt, 1);
        row.ip        = (const char*)sqlite3_column_text(stmt, 2);
        row.detail    = (const char*)sqlite3_column_text(stmt, 3);
        row.timestamp = (const char*)sqlite3_column_text(stmt, 4);
        rows.push_back(row);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    // write to json file
    std::ofstream file(outputPath_);

    file << "{\n";
    file << "  \"alerts\": [\n";

    for (int i = 0; i < (int)rows.size(); i++) {
        const AlertRow& r = rows[i];
        file << "    {\n";
        file << "      \"id\": "          << r.id           << ",\n";
        file << "      \"type\": \""      << r.type         << "\",\n";
        file << "      \"ip\": \""        << r.ip           << "\",\n";
        file << "      \"detail\": \""    << r.detail       << "\",\n";
        file << "      \"timestamp\": \"" << r.timestamp    << "\"\n";
        file << "    }";

        // no comma after last item
        if (i < (int)rows.size() - 1) file << ",";
        file << "\n";
    }

    file << "  ]\n";
    file << "}\n";

    file.close();

    std::cout << "[JSON] Exported " << rows.size()
              << " alerts to " << outputPath_ << "\n";
}
