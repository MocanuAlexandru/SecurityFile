
#include "FileEncrypt.hpp"

void FileEncrypt::setEncryptContent(std::string encryptContent) {
    this->encryptContent = encryptContent;
}

void FileEncrypt::setClearContent(std::string clearContent) {
    this->clearContent=clearContent;
}

void FileEncrypt::setEncryptKey(std::string key) {
    this->encryptKey = key;
}

std::string FileEncrypt::getClearContent() {
    return this->clearContent;
}

std::string FileEncrypt::getEncryptContent() {
    return this->encryptContent;
}

std::string FileEncrypt::getEncryptKey() {
    return this->encryptKey;
}

void FileEncrypt::setFileId(unsigned int idFile) {
    this->fileId = idFile;
}

unsigned int FileEncrypt::getFileId() {
    return this->fileId;
}

unsigned int FileEncrypt::getEncryptTime() {
    return this->encryptTime;
}

void FileEncrypt::setEncryptTime(unsigned int encryptTime) {
    this->encryptTime = encryptTime;
}

const std::string &FileEncrypt::getFileName() const {
    return fileName;
}

void FileEncrypt::setFileName(const std::string &fileName) {
    this->fileName = fileName;
}

unsigned int FileEncrypt::getUserId() const {
    return userId;
}

void FileEncrypt::setUserId(unsigned int userId) {
    this->userId = userId;
}

const std::string &FileEncrypt::getDeleteKey() const {
    return deleteKey;
}

void FileEncrypt::setDeleteKey(const std::string &deleteKey) {
    FileEncrypt::deleteKey = deleteKey;
}



