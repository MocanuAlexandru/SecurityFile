//
// Created by alex on 13.12.2020.
//

#ifndef PROJECT_DBMANAGER_HPP
#define PROJECT_DBMANAGER_HPP

#include <string>
#include <iostream>

#include <pqxx/pqxx>


class DBManager {

private:
    // Informations used for connecting to the Postgres DB instance
    const std::string hostname = "localhost";
    const std::string port = "5432";
    const std::string dbName = "SecurityFileDB";
    const std::string user = "admin";
    const std::string password = "AdminSuperSecretPassword";
    const std::string connectionString = "host=" + hostname + " port=" + port + " dbname=" + dbName + " user=" + user + " password=" + password;

    pqxx::connection dbConnection;
    pqxx::work dbWorker;

    DBManager();

public:
    DBManager(const DBManager&) = delete;
    DBManager& operator=(const DBManager&) = delete;

    static DBManager& getInstance();

    pqxx::result executeQuery(std::string query);

    template<typename ...Args>
    pqxx::result executeParametricQuery(std::string query, Args... args){
        this->dbConnection.prepare("", query);
        pqxx::result val = this->dbWorker.exec_prepared("", args...);
        int x = 1;
        return val;
    }
};


#endif //PROJECT_DBMANAGER_HPP
