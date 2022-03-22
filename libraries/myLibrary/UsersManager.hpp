//
// Created by Iulius-AlexandruCazo on 12/12/2020.
//

#ifndef SECURITYFILE_USERSMANAGER_HPP
#define SECURITYFILE_USERSMANAGER_HPP

#include <vector>

#include "UserAuth.hpp"
#include "FileManager.hpp"

namespace UsersManager {
    bool isUserRegister(UserAuth user);
    bool registerUser(UserAuth user);
    bool isAdmin(UserAuth user);
    std::vector<UserAuth> getAllUsers();
};


#endif //SECURITYFILE_USERSMANAGER_HPP
