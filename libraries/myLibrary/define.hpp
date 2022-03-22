#ifndef SECURITYFILE_DEFINE_H
#define SECURITYFILE_DEFINE_H

#include <cstdint>
#include <vector>
#include <string>
#include <iostream>


typedef std :: vector<std :: vector<uint8_t>> stateType;



uint8_t invHexaDecimal(char x);

void throwException(std :: string fileLineAndMessage);

std::string byteIntoHexa (uint8_t x);

std::string bytesIntoHexa (std :: string bytes);

uint8_t pairHexaIntoByte(std::string pairHexa);

std::string hexaMessageIntoMessage(std::string hexaMessage);

void printState(stateType state);

void printVector(std::string message);

std::string convertIntoString(std::vector<uint8_t> bytes);

void printKey(stateType key);

bool compareState(stateType state1, stateType state2);

bool compareStates(std::vector<stateType> states1, std::vector<stateType> states2);

void printVsFromMessage(std::string mess);

stateType extractVsFromMessage(std::string mess);



//void autoTestAes(AES cript, int nrMessage, int maxLengthMessage) {
//    for (int var = 0; var < nrMessage; ++var) {
//        //int messageLength = rand() % maxLengthMessage + 1;
//        std::string clearMessage;
//        for (int var1 = 0; var1 < maxLengthMessage; ++var1) {
//            clearMessage += rand() % 256;
//        }
//        std::string encMessage = cript.encMessage(clearMessage);
//        std :: cout << "Mesajul criptat in hexa: " << bytesIntoHexa(encMessage);
//        std::string hexaMessageKey = bytesIntoHexa(cript.transformKeyInMessage(cript.getLastKey()));
//        std ::cout << "\n\n\n CHEIA IN HEXA ESTE: " << hexaMessageKey;
//        stateType key = cript.transformMessageInKey(hexaMessageIntoMessage(hexaMessageKey));
//        cript.setDecKey(key);
//        std::string clearText = cript.decMessage(encMessage);
//        if (clearText != clearMessage) {
//            printKey(key); std :: cout << "\n";
//            printKey(cript.getLastKey());
//            std :: cout << '\n';
//            std :: cout << "ESTE O PROBLEMA LA PASUL: " << var << "\n";
//            std :: cout << "MESAJ CRIPTAT: "; printVector(encMessage);  std::cout<< "\n lungime mesaj CRIPTAT: " << encMessage.length() <<  '\n';
//            std :: cout << "MESAJ CLAR: " << clearMessage << "\n lungime mesaj clar: " << clearMessage.length() <<  '\n' << "MESAJ DECRIPTAT: " << clearText << "\n lungime mesaj decriptat: " << clearText.length() << "\n\n\n\n\n";*/
//            return ;
//        }
//    }
//    std :: cout << "\n MERGE BINE!";
//}
#endif //SECURITYFILE_DEFINE_H
