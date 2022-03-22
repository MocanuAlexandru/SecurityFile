#ifndef SECURITYFILE_AES_H
#define SECURITYFILE_AES_H

#include <cstdint>
#include <ctime>
#include <string>
#include <thread>

#include "define.hpp"

class AES {
private:
    int numberRounds;
    int stateLength;
    int keyLength;
    int numberThreadsForDec;
    const int wordLength = 4;
    const int stateHeight;
    enum processType {ENCRYPTION, DECRYPTION};
    const uint8_t sb;
    const uint8_t mb;
    const int byteLength;
    const uint8_t enMixColumnMat[4][4] = { { 2, 3, 1, 1}, { 1, 2, 3, 1 }, { 1, 1, 2, 3 }, { 3, 1, 1, 2 } };
    const uint8_t decMixColumnMat[4][4] = { {14, 11, 13, 9 }, { 9, 14, 11, 13 }, { 13, 9, 14, 11 }, { 11, 13, 9, 14 } };
    const uint8_t inverse[256] = { 0, 1, 141, 246, 203, 82, 123, 209, 232, 79, 41, 192, 176, 225, 229, 199, 116, 180, 170, 75, 153, 43,
                                   96, 95, 88, 63, 253, 204, 255, 64, 238, 178, 58, 110, 90, 241, 85, 77, 168, 201, 193, 10, 152, 21, 48,
                                   68, 162, 194, 44, 69, 146, 108, 243, 57, 102, 66, 242, 53, 32, 111, 119, 187, 89, 25, 29, 254, 55, 103,
                                   45, 49, 245, 105, 167, 100, 171, 19, 84, 37, 233, 9, 237, 92, 5, 202, 76, 36, 135, 191, 24, 62, 34, 240,
                                   81, 236, 97, 23, 22, 94, 175, 211, 73, 166, 54, 67, 244, 71, 145, 223, 51, 147, 33, 59, 121, 183, 151,
                                   133, 16, 181, 186, 60, 182, 112, 208, 6, 161, 250, 129, 130, 131, 126, 127, 128, 150, 115, 190, 86,
                                   155, 158, 149, 217, 247, 2, 185, 164, 222, 106, 50, 109, 216, 138, 132, 114, 42, 20, 159, 136, 249,
                                   220, 137, 154, 251, 124, 46, 195, 143, 184, 101, 72, 38, 200, 18, 74, 206, 231, 210, 98, 12, 224, 31,
                                   239, 17, 117, 120, 113, 165, 142, 118, 61, 189, 188, 134, 87, 11, 40, 47, 163, 218, 212, 228, 15, 169,
                                   39, 83, 4, 27, 252, 172, 230, 122, 7, 174, 99, 197, 219, 226, 234, 148, 139, 196, 213, 157, 248, 144,
                                   107, 177, 13, 214, 235, 198, 14, 207, 173, 8, 78, 215, 227, 93, 80, 30, 179, 91, 35, 56, 52, 104, 70,
                                   3, 140, 221, 156, 125, 160, 205, 26, 65, 28 };
    const bool subBytesMatrix[8][8] = { { 1, 0, 0, 0, 1, 1, 1, 1 }, { 1, 1, 0, 0, 0, 1, 1, 1 }, { 1, 1, 1, 0, 0, 0, 1, 1 },
                                        { 1, 1, 1, 1, 0, 0, 0, 1 }, { 1, 1, 1, 1, 1, 0, 0, 0 }, { 0, 1, 1, 1, 1, 1, 0, 0 },
                                        { 0, 0, 1, 1, 1, 1, 1, 0 }, { 0, 0, 0, 1, 1, 1, 1, 1 } };
    const bool decSubBytesMatrix[8][8] = { { 0, 0, 1, 0, 0,	1, 0, 1}, { 1, 0, 0, 1, 0, 0, 1, 0 }, { 0, 1, 0, 0, 1, 0, 0, 1 },
                                           {1, 0, 1, 0, 0, 1, 0, 0 }, { 0, 1, 0, 1, 0, 0, 1, 0 }, { 0, 0, 1, 0, 1, 0, 0, 1 },
                                           { 1, 0, 0, 1, 0, 1, 0, 0 }, { 0, 1, 0, 0, 1, 0, 1, 0 } };
    const uint8_t subByteConstant = 99;
    stateType lastKey;
    stateType decKey;
    stateType iVState;


    bool getValueOfBit(int k, uint8_t x);

    std :: vector<uint8_t> transformMessageInBytes(std :: string message);
    std :: string transformBytesInMessage(std :: vector<uint8_t>, processType);
    std :: vector<stateType>transformBytesInStates(std :: vector<uint8_t>);
    std::vector<uint8_t>transformStatesInBytes(std::vector<stateType> states);
    std :: vector<stateType> transformMessageInStates(std :: string);
    uint8_t subBytesTransformationOnByte(uint8_t inverseByte);
    uint8_t decSubytesTransformationOnByte(uint8_t byte);
    stateType subBytesTransformationOnState(stateType);
    stateType decSubBytesTransfromationOnState(stateType);
    std :: vector<stateType> subBytesTransformation(std :: vector<stateType>);
    stateType shiftRowsOnState(stateType);
    stateType decShiftRowsOnState(stateType);
    std :: vector<stateType> shiftRowsTransformation(std :: vector<stateType>);
    uint8_t prod2(uint8_t);
    uint8_t prod2k(uint8_t,uint8_t);
    uint8_t prod(uint8_t, uint8_t);
    std :: vector<uint8_t> enMixColumn(std :: vector<uint8_t>);
    std :: vector<uint8_t> decMixColumn(std :: vector<uint8_t>);
    stateType enMixColumnOnState(stateType state);
    stateType decMixColumnOnState(stateType state);
    std :: vector<stateType> mixColumnTransfromation(std :: vector<stateType>);
    uint8_t rotByte(uint8_t);
    std :: vector<uint8_t> rotWord(std :: vector<uint8_t>);
    std :: vector<uint8_t> subWord(std :: vector<uint8_t>);
    std :: vector<uint8_t> getRcon(int);
    std :: vector<uint8_t> sumWord(std :: vector<uint8_t>, std :: vector<uint8_t>);
    stateType tranState(stateType);
    std :: vector<stateType> expandsKey(stateType);
    stateType encryptState(stateType, const std::vector<stateType>&);
    stateType decryptState(stateType, const std :: vector<stateType>&);
    std :: string encryptMessage(std :: string);
    stateType addRoundKey(stateType, stateType);
    std :: vector<stateType> addRoundKeyOnStates(std :: vector<stateType>, stateType);
    std :: string transformStatesIntoMessage(std :: vector<stateType>);
    std :: vector<stateType> decStatesMessage(std :: vector<stateType>, stateType);
    void decThreadFun(std::vector<stateType>*, const std :: vector<stateType>&, const std :: vector<stateType>&, const int st, const int dr, const stateType& ivState);
    stateType generateIvState();


public:
    AES(int numberRounds = 14);
    void setDecKey(stateType);
    void setKeyLength(int keyLength);
    void setStateLength(int stateLength);
    void setNumberRounds(int numberRounds);
    void setNumberThreadForDec(int numberThreadsForDec);
    std::string encMessage(std::string message);
    std::string decMessage(std::string decMessage);
    std::string transformKeyInMessage(stateType key) {
        std::string message = "";
        for (int var1 = 0; var1 < key.size(); ++var1) {
            for (int var2 = 0; var2 < key[0].size(); ++var2) {
                message += key[var1][var2];
            }
        }
        return message;
    }

    stateType transformMessageInKey(std::string message) {
        stateType key;
        for (int var1 = 0; var1 < this->stateHeight; ++var1) {
            std::vector<uint8_t> lineFromKey;
            for (int var2 = 0; var2 < this->keyLength; ++var2) {
                lineFromKey.push_back((uint8_t)message[this->keyLength * var1 + var2]);
            }
            key.push_back(lineFromKey);
        }
        return key;
    }
    stateType getLastKey();

    stateType generateKey(unsigned int seed = time(NULL));

    std::string encMessage(std::string message, stateType key);
};


#endif //SECURITYFILE_AES_H