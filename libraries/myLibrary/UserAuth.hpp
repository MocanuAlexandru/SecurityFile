//
// Created by Iulius-AlexandruCazo on 12/10/2020.
//

#ifndef SECURITYFILE_USERAUTH_HPP
#define SECURITYFILE_USERAUTH_HPP

#include <string>
#include <exception>

#include <pqxx/pqxx>

#include "DbManager.hpp"


class UserAuth {

private:
    std::string userPassword;
    std::string userAccount;
    int userId;

public:
    UserAuth(pqxx::row);
    UserAuth(std::string userAccount, std::string userPassword);
    UserAuth(std::string userAccount, std::string userPassword, int userId);

    std::string getUserAccount();
    std::string getUserPassword();
    int getUserId();

    static UserAuth getUserByName(std::string);
};


#endif //SECURITYFILE_USERAUTH_HPP
