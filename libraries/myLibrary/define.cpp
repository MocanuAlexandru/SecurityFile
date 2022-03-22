
#include "define.hpp"

const char* hexaDecimal = "0123456789abcdef";

uint8_t invHexaDecimal(char x) {
    for (int var = 0; var < 16; ++var) {
        if (x == hexaDecimal[var])
            return var;
    }
}

void throwException(std :: string fileLineAndMessage) {
    std :: cout << "EXCEPTION: " << fileLineAndMessage;
    exit(1);
}

std::string byteIntoHexa (uint8_t x) {
    std::string hexa;
    int firstVal = 0;
    int nextVal = 0;
    for (int var = 0; var < 8; ++var) {
        if (var < 4) {
            firstVal += (1 << var) * ((x & (1 << var)) > 0);
        } else {
            nextVal += (1 << (var - 4)) * ((x & (1 << (var))) > 0);
        }
    }
    hexa += hexaDecimal[nextVal];
    hexa += hexaDecimal[firstVal];
    return hexa;
}

std::string bytesIntoHexa (std :: string bytes) {
    std::string hexaRep;
    for (int var = 0 ; var < bytes.length(); ++var) {
        hexaRep += byteIntoHexa((uint8_t)bytes[var]);
    }
    return hexaRep;
}

uint8_t pairHexaIntoByte(std::string pairHexa) {
    int nextVal = invHexaDecimal(pairHexa[0]);
    int firstVal = invHexaDecimal(pairHexa[1]);
    uint8_t byte = 0;
    for (int var = 0; var < 8; ++var) {
        if (var < 4) {
            byte += (1 << var) * ((firstVal & (1 << var)) > 0);
        } else {
            byte += (1 << var) * ((nextVal & (1 << (var - 4))) > 0);
        }
    }
    return byte;
}

std::string hexaMessageIntoMessage(std::string hexaMessage) {
    std::string message;
    for (int var = 0; var < hexaMessage.length(); var = var + 2) {
        std::string pairHexa = "";
        pairHexa += hexaMessage[var];
        pairHexa += hexaMessage[var + 1];
        message += pairHexaIntoByte(pairHexa);
    }
    return message;
}

void printState(stateType state) {
    for (int var = 0; var < state.size(); ++var) {
        for (int var1 = 0; var1 < state[0].size(); ++var1) {
            std :: cout << state[var][var1] + 0 << ' ';
        }
        std :: cout << '\n';
    }
}

void printVector(std::string message) {
    std :: cout << "{";
    for (int var = 0; var < message.length(); ++var) {
        std :: cout << (uint8_t)message[var] + 0 << ((var == (message.length() - 1)) ? ' ':',');;
    }
    std::cout << "}";
}

std::string convertIntoString(std::vector<uint8_t> bytes) {
    std::string message = "";
    for (int var = 0; var < bytes.size() ; ++var) {
        message += bytes[var];
    }
    return message;
}

void printKey(stateType key) {
    std :: cout << '{';
    for (int var1 = 0; var1 < key.size(); ++var1) {
        std::cout << '{';
        for (int var2 = 0; var2 < key[0].size(); ++var2) {
            std::cout << (uint8_t)key[var1][var2] + 0 << ((var2 == (key[0].size() - 1)) ? ' ':',');
        }
        std::cout << ((var1 == (key.size() -1)) ? "}" : "},");
    }
    std::cout << "}";
}

bool compareState(stateType state1, stateType state2) {
    if ( state1.size() != state2.size() || state1[0].size() != state2[0].size()) return false;
    for (int var1 = 0; var1 < state1.size(); ++var1) {
        for (int var2 = 0; var2 < state1[0].size(); ++var2) {
            if(state1[var1][var2] != state2[var1][var2]) return false;
        }
    }
    return true;
}

bool compareStates(std::vector<stateType> states1, std::vector<stateType> states2) {
    if (states1.size() != states2.size()) return false;
    for (int var = 0; var < states1.size(); ++var) {
        if (!compareState(states1[var], states2[var])) return false;
    }
    return true;
}

void printVsFromMessage(std::string mess) {
    std :: cout << "AICI ESTE IV: ";
    for (int k = 0; k < 16; ++k) {
        int var = mess.length() - 16 + k;
        if (k % 4) {
            std :: cout << ' ' << (unsigned char)mess[var] + 0;
        } else {
            std :: cout << '\n' << (unsigned char)mess[var] + 0;
        }
    }
    std :: cout << '\n';
}

stateType extractVsFromMessage(std::string mess) {
    stateType vs;
    std::vector<uint8_t> line;
    for (int k = 0; k < 16; ++k) {
        int var = mess.length() - 16 + k;
        if (k % 4 || k == 0) {
            line.push_back((unsigned char)mess[var]);
        } else {
            vs.push_back(std ::vector<uint8_t> (line));
            line = {(unsigned char)mess[var]};
        }
        if (k == 15) vs.push_back(line);
    }
    return vs;
}
