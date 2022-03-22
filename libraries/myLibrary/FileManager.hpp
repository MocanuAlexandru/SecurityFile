#ifndef SECURITYFILE_FILEMANAGER_HPP
#define SECURITYFILE_FILEMANAGER_HPP

#include <string>
#include <fstream>
#include <filesystem>

#include "UserAuth.hpp"
#include "FileEncrypt.hpp"
#include "AES.hpp"
#include "define.hpp"
#include "sha256.h"

namespace FileManager {

    void createDirectoryForUser(UserAuth);
    FileEncrypt addFile(std::string fileName, std::string clearContent, UserAuth user);
    FileEncrypt getFile(FileEncrypt file);
    std::vector< std::pair <unsigned int, std::string> > getAllFileForUser(UserAuth user);
    void deleteFile(FileEncrypt file, UserAuth user);
};


#endif //SECURITYFILE_FILEMANAGER_HPP
