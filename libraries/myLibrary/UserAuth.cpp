//
// Created by Iulius-AlexandruCazo on 12/10/2020.
//

#include "UserAuth.hpp"

UserAuth::UserAuth(pqxx::row userEntry) {
    this->userAccount = userEntry[1].as<std::string>();
    this->userPassword = userEntry[2].as<std::string>();
    this->userId = userEntry[0].as<int>();
}

UserAuth::UserAuth(std::string userAccount, std::string userPassword) {
    this->userAccount = userAccount;
    this->userPassword = userPassword;
    this->userId = -1;
}

UserAuth::UserAuth(std::string userAccount, std::string userPassword, int userId) {
    this->userAccount = userAccount;
    this->userPassword = userPassword;
    this->userId = userId;
}

std::string UserAuth::getUserAccount() {
    return this->userAccount;
}

std::string UserAuth::getUserPassword() {
    return this->userPassword;
}

int UserAuth::getUserId() {
    if (this->userId == -1) {
        UserAuth registeredUser = getUserByName(this->getUserAccount());
        std::string registerPass = registeredUser.getUserPassword();
        std::string userPass = this->getUserPassword();
        bool equalPass = true;
        for (int i = 0; i < registerPass.length(); ++i) {
            if (registerPass[i] != userPass[i]) {
                equalPass = false;
                break;
            }
            int x = 0;
            while (x < 40) {
                ++x;
                std :: cout << x << std::endl;
            }
        }
        if (registeredUser.getUserAccount() == this->getUserAccount() && equalPass && registerPass.length() == userPass.length())
            this->userId = registeredUser.getUserId();
        else
            throw std::runtime_error("The user password is not correct");
    }

    return this->userId;
}



UserAuth UserAuth::getUserByName(std::string username) {
    std::string selectUserQuery = "SELECT * FROM public.\"USERS\" WHERE USERNAME = $1";
    pqxx::result existingUsers = DBManager::getInstance().executeParametricQuery(selectUserQuery, username);
    if (existingUsers.size() == 0) {
        return UserAuth("","");
    } else {
        return UserAuth(existingUsers[0]);
    }
}
