//
// Created by alex on 13.12.2020.
//

#include "DbManager.hpp"

DBManager::DBManager() : dbConnection(connectionString), dbWorker(dbConnection) {}

DBManager& DBManager::getInstance() {
    static DBManager instance;

    return instance;
}

pqxx::result DBManager::executeQuery(std::string query) {
    return this->dbWorker.exec(query);
}


