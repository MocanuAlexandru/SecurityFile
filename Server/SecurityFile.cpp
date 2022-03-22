#include <iostream>
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "FileManager.hpp"
#include "FileEncrypt.hpp"

#include "UsersManager.hpp"
#include "sha256.h"
#include <exception>
UserAuth takeUserFromHeaders (httplib::Headers headers) {
    const std::string user = "user";
    const std::string pass = "pass";
    std::string userName;
    std::string password;
    for (auto &it : headers) {
        if(it.first == user) {
            userName = it.second;
        }
        if (it.first == pass) {
            password = it.second;
        }
    }
    return UserAuth(userName, password);
}
int main(){
    const std::string registerMessage = "WELCOME TO THE SECURITY FILE!\nYou can write 'help' for see all possible commands\n";
    const std::string noRegisterMessage = "YOUR USER ISN'T REGISTER!\n";
    const std::string admin = "isAdmin";
    const std::string noAdmin = "isn'tAdmin";
    httplib::Server svr;


   svr.Post("/crypt",
             [&](const httplib::Request &req, httplib::Response &res, const httplib::ContentReader &content_reader) {
                         std::string body;
                         if (req.is_multipart_form_data()) {
                             httplib::MultipartFormDataItems files;
                             content_reader(
                                     [&](const httplib::MultipartFormData &file) {
                                         files.push_back(file);
                                         return true;
                                     },
                                     [&](const char *data, size_t data_length) {
                                         files.back().content.append(data, data_length);
                                         return true;
                                     });
                         } else {
                             content_reader([&](const char *data, size_t data_length) {
                                 body.append(data, data_length);
                                 return true;
                             });


                         UserAuth userAuth = takeUserFromHeaders(req.headers);
                         if (UsersManager::isUserRegister(userAuth)) {
                             nlohmann::json fileJson = nlohmann::json::parse(body);
                             FileEncrypt fileEncrypt = FileManager::addFile(fileJson["fileName"],fileJson["fileContent"],userAuth);
                             nlohmann::json encryptJsonFile;
                             encryptJsonFile["keyEncrypt"] = fileEncrypt.getEncryptKey();
                             encryptJsonFile["keyDelete"] = fileEncrypt.getDeleteKey();
                             encryptJsonFile["timeEncrypt"] = std::to_string(fileEncrypt.getEncryptTime());
                             encryptJsonFile["idFile"] = std::to_string(fileEncrypt.getFileId());
                             res.set_content(encryptJsonFile.dump(), "text/plain");
                         } else {
                             res.status = 422;
                         }
                 }
             });

    svr.Post("/register",
            [&](const httplib::Request &req, httplib::Response &res) {
                nlohmann::json jsonObj = nlohmann::json::parse(req.body);
                UserAuth userAuth(jsonObj["user"],jsonObj["pass"]);
               if (UsersManager::registerUser(userAuth)) {
                   res.set_content("You have successfully registered!\n", "text/plain");
               } else {
                   res.set_content("Your user is used of another person, try again with different username!\n", "text/plain");
               }
            });

    svr.Post("/login", [&](const httplib::Request &req, httplib::Response &res) {
        nlohmann::json jsonObj = nlohmann::json::parse(req.body);
        UserAuth userAuth(jsonObj["user"],jsonObj["pass"]);
        if (UsersManager::isUserRegister(userAuth)) {
            res.set_content(registerMessage, "text/plain");
        } else {
            res.set_content(noRegisterMessage, "text/plain");
        }
    });

    svr.Get("/getAllUsers", [&](const httplib::Request &req, httplib::Response &res) {
        if (UsersManager::isAdmin(takeUserFromHeaders(req.headers))) {
            std::vector<UserAuth> allUsers = UsersManager::getAllUsers();
            nlohmann::json usersJson;
            for (int var = 0; var < allUsers.size(); ++var) {
                usersJson[std::to_string(allUsers[var].getUserId())] = allUsers[var].getUserAccount();
            }
            res.set_content(usersJson.dump(), "text/plain");
        } else {
            res.status = 401;
        }
    });

    svr.Get("/isAdmin", [&](const httplib::Request &req, httplib::Response &res) {
        if (UsersManager::isAdmin(takeUserFromHeaders(req.headers))) {
            res.set_content(admin, "text/plain");
        } else {
            res.set_content(noAdmin, "text/plain");
        }});

    svr.Post("/getFile", [&](const httplib::Request &req, httplib::Response &res) {
        if (UsersManager::isUserRegister(takeUserFromHeaders(req.headers))) {
            nlohmann::json encryptFileJson = nlohmann::json::parse(req.body);
            FileEncrypt fileEncrypt;
            fileEncrypt.setEncryptKey(encryptFileJson["encryptKey"]);
            fileEncrypt.setFileId(std::stoi(std::string(encryptFileJson["idFile"])));
            FileEncrypt decryptFile = FileManager::getFile(fileEncrypt);
            nlohmann::json decryptFileJson;
            decryptFileJson["content"] = decryptFile.getClearContent();
            decryptFileJson["fileName"] = decryptFile.getFileName();
            res.set_content(decryptFileJson.dump(), "text/plain");
        } else {
            res.status = 401;
        }
        });

    svr.Get("/getAllFiles", [&](const httplib::Request &req, httplib::Response &res) {
        UserAuth userAuth = takeUserFromHeaders(req.headers);
        if (UsersManager::isUserRegister(userAuth)) {
            std::vector<std::pair<unsigned int, std::string> > allFiles = FileManager::getAllFileForUser(userAuth);
            nlohmann::json allFilesJson;
            for (auto &pair : allFiles) {
                allFilesJson[std::to_string(pair.first)] = pair.second;
            }
            res.set_content(allFilesJson.dump(), "text/plain");
        } else {
            res.status = 401;
        }
    });

    svr.Delete("/deleteFile", [&](const httplib::Request &req, httplib::Response &res) {
            UserAuth userAuth = takeUserFromHeaders(req.headers);
            if (UsersManager::isUserRegister(userAuth)) {
                nlohmann::json deleteFileJson = nlohmann::json::parse(req.body);
                FileEncrypt deleteFile;
                deleteFile.setDeleteKey(std::string(deleteFileJson["keyDelete"]));
                deleteFile.setFileId(std::stoi(std::string(deleteFileJson["idFile"])));
                FileManager::deleteFile(deleteFile, userAuth);
            } else {
                res.status = 401;
            }
        });

    svr.listen("0.0.0.0", 8080);

    return 0;
}