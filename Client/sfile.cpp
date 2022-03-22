//
// Created by cazoni on 12/13/20.
//
#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>
#include <iomanip>
#include "httplib.h"
#include "sha256.h"


std::string takeFileNameFromPath(std::string pathFile) {
    std::string delimiter = "/";
    std::string fileName = pathFile;
    int currentPozDelimiter = fileName.find(delimiter);
    while (currentPozDelimiter != -1) {
        fileName = fileName.substr(currentPozDelimiter + 1, fileName.size());
        currentPozDelimiter = fileName.find(delimiter);
    }
    return fileName;
}

std::string getTimestamp(unsigned int seconds) {
    // get a precise timestamp as a string
    std::time_t nowAsTimeT = seconds;
    std::stringstream nowSs;
    nowSs
            << std::put_time(std::localtime(&nowAsTimeT), "%a %b %d %Y %T")
            << '.' << std::setfill('0') << std::setw(3);
    return nowSs.str();
}

int main(int argc, char* argv[]) {
    const std::string  REGISTER = "register";
    const std::string LOGIN = "login";
    const std::string admin = "isAdmin";
    const std::string noAdmin = "isn'tAdmin";
    const std::string noValidCommand = "Your command isn't recognize";
    const std::string registerMessage = "WELCOME TO THE SECURITY FILE!\nYou can write 'help' for see all possible commands\n";
    const std::string deleteFile = "delete";
    const std::string decryptFile = "decrypt";
    const std::string cryptFile = "crypt";
    const std::string getFiles = "getFiles";
    const std::string getAllUsers = "getAllUsers";
    const std::string help = "help";
    const std::string quit = "quit";
    const std::string noRegisterMessage = "YOUR USER ISN'T REGISTER!\n";
    const std::string internalError = "Internal errors, try again command";
    const std::vector<std::string> allPossibleCommands = {
            "crypt [pathFile]",
            "decrypt [idFile] [encryptKey]",
            "delete [idFile] [deleteKey]",
            "getFiles",
            "getAllUsers",
            "help",
            "quit"
    };
    const int maxKbSize = 101;
    const int adminCommand = 4;
    httplib::Client client("http://localhost:8080");
    SHA256 sha256;
    bool isFirstRound = true;
    if (argc == 2) {
        std::string param = argv[argc-1];
        if (param == LOGIN) {
            std::string user, pass;
            std::cout << "user: ";
            std::cin >> user;
            std::cout << "password: ";
            std::cin >> pass;
            nlohmann::json jsonUser;
            jsonUser["user"] = user;
            jsonUser["pass"] = sha256(pass);
            httplib::Result svResponseLogin = client.Post("/login", jsonUser.dump(), "text/plain");
            if (svResponseLogin->status == 200) {
                std::string svBodyLogin = svResponseLogin->body;
                if (svBodyLogin == registerMessage) {
                    std::cout << svBodyLogin;
                    httplib::Headers cookieHeaders = {
                            { "user", user },
                            {"pass", sha256(pass) }
                    };
                    httplib::Result isAdminResponse = client.Get("/isAdmin", cookieHeaders);
                    std::string isAdmin;
                    if (isAdminResponse->status == 200) {
                        isAdmin = isAdminResponse->body;
                    } else {
                        std::cout << internalError;
                        return 0;
                    }
                    while (true) {
                        std::cout << "\n(sfile) ";
                        std::string commandString;
                        if (isFirstRound) {
                            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                            isFirstRound = false;
                        }
                        getline(std::cin, commandString);
                        //std::cin>> commandString;
                        std::istringstream ss(commandString);
                        std::string word;
                        std::vector<std::string> commandVector;
                        while (ss >> word) {
                            commandVector.push_back(word);
                        }
                        int commandLength = commandVector.size();
                        if (commandLength == 3) {
                            if (commandVector[0] == deleteFile) {
                                std::string idFile = commandVector[1];
                                std::string keyDelete = commandVector[2];
                                nlohmann::json fileForDeleteJson;
                                fileForDeleteJson["idFile"] = idFile;
                                fileForDeleteJson["keyDelete"] = keyDelete;
                                httplib::Result deleteFileResponse = client.Delete("/deleteFile", cookieHeaders, fileForDeleteJson.dump(), "text/plain");
                                if (deleteFileResponse->status == 200) {
                                    std::cout << "Your file was deleted with success\n";
                                } else {
                                    std::cout << internalError << '\n';
                                }
                                continue;
                            }
                            if (commandVector[0] == decryptFile) {
                                std::string idFile = commandVector[1];
                                std::string encryptKey = commandVector[2];
                                nlohmann::json encryptFile;
                                encryptFile["idFile"] = idFile;
                                encryptFile["encryptKey"] = encryptKey;
                                httplib::Result decryptResponse = client.Post("/getFile", cookieHeaders, encryptFile.dump(), "text/plain");
                                if (decryptResponse->status == 200) {
                                    nlohmann::json decryptFileJson = nlohmann::json::parse(decryptResponse->body);
                                    std::ofstream out(std::string("decryptFiles/") + std::string(decryptFileJson["fileName"]));
                                    out << std::string(decryptFileJson["content"]);
                                    std::cout << "Successfully decrypted! Your file is in decryptFiles directory!\n";
                                } else {
                                    std::cout << internalError << "\n";
                                }
                                continue;
                            }
                        }
                        if (commandLength == 2) {
                            if (commandVector[0] == cryptFile) {
                                std::string path = commandVector[1];
                                std::ifstream f(path, std::ios::binary | std::ios::ate);
                                if (f.tellg()/1024 < maxKbSize) {
                                    f.close();
                                    f.open(path);
                                    std::string fileContent((std::istreambuf_iterator<char>(f)),
                                                            std::istreambuf_iterator<char>());
                                    if (fileContent.size()) {
                                        std::string fileName = takeFileNameFromPath(path);
                                        nlohmann::json fileJson;
                                        fileJson["fileContent"] = fileContent;
                                        fileJson["fileName"] = fileName;
                                        httplib::Result cryptResponse = client.Post("/crypt", cookieHeaders,
                                                                                    fileJson.dump(), "text/plain");
                                        if (cryptResponse->status == 200) {
                                            nlohmann::json encryptFile = nlohmann::json::parse(cryptResponse->body);
                                            std::string timeEncrypt = encryptFile["timeEncrypt"];
                                            std::string encryptKey = encryptFile["keyEncrypt"];
                                            std::string idFile = encryptFile["idFile"];
                                            std::string deleteKey = encryptFile["keyDelete"];
                                            std::ofstream out;
                                            out.open("infoYourFiles.txt", std::ios_base::app);
                                            out << "fileName: " << fileName << " idFile: " << idFile << " encryptKey: "
                                                << encryptKey << " deleteKey: " << deleteKey << '\n';
                                            std::cout << "Your file was successfully encrypted to date: "
                                                      << getTimestamp(stoi(timeEncrypt))
                                                      << ", and its associated keys are at the end of the infoYourFiles.txt\n";
                                        } else {
                                            std::cout << internalError << '\n';
                                        }
                                    } else {
                                        std::cout << "Your path is wrong or file is empty\n";
                                    }
                                } else {
                                    std::cout << "Your file is too large!\n\n";
                                }
                                f.close();
                                continue;
                            }
                        }
                        if (commandLength == 1) {
                            if (commandVector[0] == getFiles) {
                                httplib::Result getFilesResponse = client.Get("/getAllFiles", cookieHeaders);
                                bool haveFiles = false;
                                if (getFilesResponse->status == 200) {
                                    nlohmann::json allFilesJson = nlohmann::json::parse(getFilesResponse->body);
                                    for (auto &x : allFilesJson.items()) {
                                        std::string fileLine = std::string(x.key()) + ":  " + std::string(x.value()) + "\n";
                                        std::cout << fileLine;
                                        haveFiles = true;
                                    }
                                    if(!haveFiles) {
                                        std::cout << "You don't have files! \n";
                                    }
                                } else {
                                    std::cout << internalError << "\n";
                                }
                                continue;
                            }
                            if (commandVector[0] == getAllUsers) {
                                if (isAdmin== admin) {
                                    httplib::Result getAllUserResponse = client.Get("/getAllUsers", cookieHeaders);
                                    if (getAllUserResponse->status == 200) {
                                        nlohmann::json allUsersJson = nlohmann::json::parse(getAllUserResponse->body);
                                        for (auto &x : allUsersJson.items()) {
                                            std::string userLine = std::string(x.key()) + ":  " + std::string(x.value()) + "\n";
                                            std::cout << userLine;
                                        }
                                    } else {
                                        std::cout << internalError;
                                    }
                                } else if (isAdmin== noAdmin) {
                                    std::cout << noValidCommand;
                                }
                                continue;
                            }

                            if (commandVector[0] == help) {
                                for (int var = 0; var < allPossibleCommands.size(); ++var) {
                                    if (isAdmin != admin && var == adminCommand) continue;
                                    std::cout << allPossibleCommands[var] << '\n';
                                }
                                continue;
                            }

                            if (commandVector[0] == quit) {
                                break;
                            }
                        }
                         std::cout << noValidCommand;
                    }

                } else {
                   std::cout <<svBodyLogin;
                }
            } else {
                std::cout << internalError;
            }
        } else if (param == REGISTER) {
            nlohmann::json jsonUser;
            std::string user, pass;
            std::cout << "username: "; std::cin >> user;
            std::cout << "password: "; std::cin >> pass;
            jsonUser["user"] = user;
            jsonUser["pass"] = sha256(pass);
            httplib::Result svReponse = client.Post("/register", jsonUser.dump(), "text/plain");
            if (svReponse->status == 200) {
                std::cout << svReponse->body;
            } else {
                std::cout << internalError;
            }
        } else {
            std::cout << "Parameter isn't known!\n";
        }
    } else {
        std::cout << "Parameter isn't known!\n";
    }
    return 0;
}

