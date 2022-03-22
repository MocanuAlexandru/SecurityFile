#include "FileManager.hpp"

namespace {
    const std::filesystem::path rootPath = std::filesystem::current_path().remove_filename() / "encrypted_files";
    unsigned int saveTime = -1;

    FileEncrypt encryptFile(AES aesObject,  FileEncrypt file, UserAuth user) {
        std::string encryptedContent = aesObject.encMessage(file.getClearContent(), aesObject.getLastKey());
        file.setEncryptContent(encryptedContent);

        file.setEncryptTime(saveTime);

        return file;
    }

    FileEncrypt getFileById(unsigned int fileId) {
        std::string querySelectFile = "SELECT * FROM public.\"ENCRYPTED_FILES\" WHERE FILE_ID = $1";
        pqxx::result fileResult = DBManager::getInstance().executeParametricQuery(querySelectFile, fileId);
        if (fileResult.size() != 1) {
            throw std::runtime_error("Couldn't find a file with the given id.");
        }

        FileEncrypt foundFile;
        foundFile.setFileId(fileResult[0][0].as<unsigned int>());
        foundFile.setUserId(fileResult[0][1].as<unsigned int>());
        foundFile.setFileName(fileResult[0][2].as<std::string>());
        foundFile.setEncryptKey(fileResult[0][3].as<std::string>());
        foundFile.setDeleteKey(fileResult[0][4].as<std::string>());

        return foundFile;
    }

    std::vector< std::pair<unsigned int, std::string> > getAllFilesByUserId(unsigned int userId) {
        std::string querySelectFiles = "SELECT FILE_ID, FILE_PATH FROM public.\"ENCRYPTED_FILES\" WHERE USER_ID = $1";
        pqxx::result foundFiles = DBManager::getInstance().executeParametricQuery(querySelectFiles, userId);

        std::vector< std::pair<unsigned int, std::string> > results;
        for (int i=0; i<foundFiles.size(); ++i) {
            results.push_back({foundFiles[i][0].as<unsigned int>(), foundFiles[i][1].as<std::string>()});
        }

        return results;
    }

    UserAuth getUserById(unsigned int userId) {
        std::string querySelectFile = "SELECT * FROM public.\"USERS\" WHERE USER_ID = $1";
        pqxx::result userResult = DBManager::getInstance().executeParametricQuery(querySelectFile, userId);
        if (userResult.size() != 1) {
            throw std::runtime_error("Couldn't find a file with the given id.");
        }

        UserAuth foundUser(userResult[0][1].as<std::string>(), userResult[0][2].as<std::string>());

        return foundUser;
    }
}

void FileManager::createDirectoryForUser(UserAuth user) {
    std::string folderName = user.getUserAccount();
    if(not (std::filesystem::create_directory(rootPath / folderName))) {
        throw std::runtime_error("Creation of folder " + folderName + " has failed!!!");
    }
}

FileEncrypt FileManager::addFile(std::string fileName, std::string clearContent, UserAuth user) {

    // Generate encryption key
    std::string querySelectLastKey = "SELECT NEXTVAL('public.\"ENCRYPTED_FILES_file_id_seq\"')";
    pqxx::result lastId = DBManager::getInstance().executeQuery(querySelectLastKey);
    unsigned int fileId = lastId[0][0].as<unsigned int>();
    unsigned int userId = user.getUserId();
    saveTime = time(NULL);
    unsigned int seed = fileId + userId + saveTime;

    AES aesObject;
    aesObject.generateKey(seed);
    stateType encryptionKey = aesObject.getLastKey();
    std::string encryptionKeyAsMessage = aesObject.transformKeyInMessage(encryptionKey);
    std::string encryptionKeyAsHex = bytesIntoHexa(encryptionKeyAsMessage);

    // Add entry for file in database
    SHA256 shaObject;
    std::string hashEncKey = shaObject(encryptionKeyAsHex);
    std::string deleteKey = shaObject(clearContent);
    std::string hashDeleteKey = shaObject(deleteKey);
    std::string insertQuery = "INSERT INTO public.\"ENCRYPTED_FILES\"(FILE_ID, USER_ID, FILE_PATH, HASH_ENC_KEY, HASH_DEL_KEY) VALUES ($1, $2, $3, $4, $5)";
    DBManager::getInstance().executeParametricQuery(insertQuery, fileId, userId, fileName, hashEncKey, hashDeleteKey);
    DBManager::getInstance().executeQuery("COMMIT");

    // Encrypt file
    FileEncrypt newFileEntry;
    newFileEntry.setClearContent(clearContent);
    newFileEntry.setEncryptKey(encryptionKeyAsHex);
    newFileEntry.setFileId(fileId);
    newFileEntry.setDeleteKey(deleteKey);
    newFileEntry = encryptFile(aesObject, newFileEntry, user);

    // Write file
    std::ofstream file((rootPath / user.getUserAccount() / std::to_string(fileId)).u8string());
    std::string encryptedContentAsHex = bytesIntoHexa(newFileEntry.getEncryptContent());
    file << encryptedContentAsHex;
    file.close();

    return newFileEntry;
}

FileEncrypt FileManager::getFile(FileEncrypt providedFileInfo) {
    unsigned int fileId = providedFileInfo.getFileId();
    FileEncrypt storedFile = getFileById(fileId);
    UserAuth owner = getUserById(storedFile.getUserId());

    SHA256 shaObject;
    std::string hashKey = shaObject(providedFileInfo.getEncryptKey());
    if (hashKey != storedFile.getEncryptKey()) {
        throw std::runtime_error("The decryption can't be performed because the provided key is not correct!");
    }

    // Read from the encrypted file
    std::filesystem::path filePath = rootPath / owner.getUserAccount() / std::to_string(fileId);
    std::ifstream file(filePath.u8string());
    std::stringstream fileContent;
    fileContent << file.rdbuf();
    std::string encryptedContent = hexaMessageIntoMessage(fileContent.str());
    storedFile.setEncryptContent(encryptedContent);

    // Decrypt the file content
    AES aesObject;
    std::string decryptionKeyAsString = hexaMessageIntoMessage(providedFileInfo.getEncryptKey());
    stateType decryptionKey = aesObject.transformMessageInKey(decryptionKeyAsString);
    aesObject.setDecKey(decryptionKey);
    std::string clearContent = aesObject.decMessage(storedFile.getEncryptContent());

    FileEncrypt decryptedFile;
    decryptedFile.setClearContent(clearContent);
    decryptedFile.setFileName(storedFile.getFileName());

    return decryptedFile;
}

void FileManager::deleteFile(FileEncrypt providedFileInfo, UserAuth user) {
    unsigned int fileId = providedFileInfo.getFileId();
    FileEncrypt storedFile = getFileById(fileId);
    UserAuth owner = user;

    SHA256 shaObject;
    std::string hashDeleteKey = shaObject(providedFileInfo.getDeleteKey());
    std::cout << hashDeleteKey << std::endl;
    std::cout << storedFile.getDeleteKey() << std::endl;
    if (hashDeleteKey != storedFile.getDeleteKey() || user.getUserId() != storedFile.getUserId()) {
        throw std::runtime_error("The delete can't be performed because the provided key is not correct or the user does not have this privilege!");
    }

    // Delete the encrypted file
    std::filesystem::path filePath = rootPath / owner.getUserAccount() / std::to_string(fileId);
    std::filesystem::remove(filePath);

    // Delete the entry from the database
    std::string queryDelete = "DELETE FROM public.\"ENCRYPTED_FILES\" WHERE FILE_ID = $1";
    DBManager::getInstance().executeParametricQuery(queryDelete, fileId);
    DBManager::getInstance().executeQuery("COMMIT");

}

std::vector<std::pair<unsigned int, std::string> > FileManager::getAllFileForUser(UserAuth user) {
    unsigned int userId = user.getUserId();

    return getAllFilesByUserId(userId);
}
