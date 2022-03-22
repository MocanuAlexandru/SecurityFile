//
// Created by Iulius-AlexandruCazo on 12/12/2020.
//

#include "UsersManager.hpp"

bool UsersManager::isUserRegister(UserAuth user) {
    try {
        user.getUserId();
        return true;
    }
    catch (std::exception&) {
        return false;
    }
}

bool UsersManager::registerUser(UserAuth user) {
    if (UserAuth::getUserByName(user.getUserAccount()).getUserAccount() != "") {
        return false;
    }

    // Create user
    std::string insertUserQuery = "INSERT INTO public.\"USERS\"(USERNAME, HASH_PASSWORD) VALUES ($1, $2)";
    DBManager::getInstance().executeParametricQuery(insertUserQuery, user.getUserAccount(), user.getUserPassword());
    DBManager::getInstance().executeQuery("COMMIT");

    FileManager::createDirectoryForUser(user);

    return true;
}

bool UsersManager::isAdmin(UserAuth user) {
    UserAuth adminUser = UserAuth::getUserByName("admin");
    std::string adminPass = adminUser.getUserPassword();
    std::string userPass = user.getUserPassword();
    bool equalPass = true;
    for (int i = 0; i < adminPass.length(); ++i) {
        if (adminPass[i] != userPass[i]) {
            equalPass = false;
            break;
        }
        int x = 0;
        while (x < 40) {
            ++x;
            std :: cout << x << std::endl;
        }
    }
    if (adminUser.getUserAccount() == user.getUserAccount() && equalPass && adminPass.length() == userPass.length()) return true;

    return false;
}

std::vector<UserAuth> UsersManager::getAllUsers() {
    std::string query = "SELECT USER_ID, USERNAME FROM public.\"USERS\"";
    pqxx::result userEntries = DBManager::getInstance().executeQuery(query);

    std::vector<UserAuth> users;
    for (int i=0; i<userEntries.size(); ++i) {
        users.push_back(UserAuth(userEntries[i][1].as<std::string>(), "", userEntries[i][0].as<int>()));
    }

    return users;
}