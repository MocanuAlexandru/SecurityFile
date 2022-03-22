//
// Created by Iulius-AlexandruCazo on 12/12/2020.
//

#ifndef SECURITYFILE_FILEENCRYPT_HPP
#define SECURITYFILE_FILEENCRYPT_HPP

#include<string>

class FileEncrypt {

private:
    std::string encryptContent;
    std::string clearContent;
    std::string encryptKey;
    std::string deleteKey;
    std::string fileName;
    unsigned int fileId;
    unsigned int userId;
    unsigned int encryptTime;

public:
    const std::string &getDeleteKey() const;

    void setDeleteKey(const std::string &deleteKey);

    void setEncryptKey(std::string key);
    void setClearContent(std::string clearContent);
    void setEncryptContent(std::string encryptContent);
    void setFileId(unsigned int idFile);
    void setEncryptTime(unsigned int encryptTime);
    unsigned int getFileId();
    std::string getEncryptKey();
    std::string getClearContent();
    std::string getEncryptContent();
    unsigned int getEncryptTime();
    const std::string &getFileName() const;
    void setFileName(const std::string &fileName);
    unsigned int getUserId() const;
    void setUserId(unsigned int userId);
};


#endif //SECURITYFILE_FILEENCRYPT_HPP
