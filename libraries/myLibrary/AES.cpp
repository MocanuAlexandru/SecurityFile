#include "AES.hpp"

AES :: AES(int numberRounds) : stateHeight(4), mb(128), sb(27), byteLength(8) {
    this->numberRounds = numberRounds;
    this->numberThreadsForDec = 3;
    this->stateLength = 4;
    this->keyLength = 8;
}

void AES::setStateLength(int stateLength) {
    this->stateLength = stateLength;
}

void AES::setKeyLength(int keyLength) {
    this->keyLength = keyLength;
}

bool AES::getValueOfBit(int k, uint8_t x) {
    return x & (1 << k);
}


std :: vector<uint8_t> AES ::transformMessageInBytes(std :: string message) {
    const int textLength = 4 * this->stateLength;
    message += (char)1;
    int nrPadding = textLength - message.length() % textLength;
    for (int k = 0; k < nrPadding % textLength; ++k) message += (char)0;
    std :: vector<uint8_t> bytesFromMessage;
    for (int nrChar = 0; nrChar < message.length(); ++nrChar) {
        bytesFromMessage.push_back((uint8_t)message[nrChar]);
    }
    return bytesFromMessage;
}

std::vector<uint8_t> AES::transformStatesInBytes(std::vector<stateType> states) {
    std::vector<uint8_t> bytesFromStates;
    for (int var = 0; var < states.size(); ++var) {
        for (int var1 = 0; var1 < this->stateHeight; ++var1) {
            for(int var2 = 0; var2 <this->stateLength; ++var2) {
                bytesFromStates.push_back(states[var][var1][var2]);
            }
        }
    }
    return  bytesFromStates;
}
std :: string AES ::transformBytesInMessage(std::vector<uint8_t> bytes, processType ptype) {
    int lastPozFromMessage= bytes.size() - 1;
    if (ptype == DECRYPTION) {
        while (bytes[lastPozFromMessage] != 1) --lastPozFromMessage;
        --lastPozFromMessage;
    }
    std :: string message = "";
    for (int var = 0; var <= lastPozFromMessage; ++var) {
        message += bytes[var];
    }
    return message;
}

std :: vector<stateType> AES ::transformBytesInStates(std :: vector<uint8_t> vectorOfBytes) {
    std :: vector<stateType> states;
    for (int var1 = 0; var1 < vectorOfBytes.size(); var1 += stateHeight * stateLength) {
        std :: vector<std :: vector<uint8_t>> state;
        for (int var2 = 0; var2 < stateHeight; ++var2) {
            std :: vector<uint8_t> lineFromState;
            for (int var3 = 0; var3 < stateLength; ++var3) {
                lineFromState.push_back(vectorOfBytes[var1 + var2 * stateLength + var3]);
            }
            state.push_back(lineFromState);
        }
        states.push_back(state);
    }
    return states;
}

std :: vector<stateType> AES::transformMessageInStates(std::string message) {
    return this->transformBytesInStates(this->transformMessageInBytes(message));
}

uint8_t AES::subBytesTransformationOnByte(uint8_t byte) {
    uint8_t newByte = 0;
    const uint8_t inverseByte = this->inverse[byte];

    for (int var1 = 0; var1 < this->byteLength; ++var1) {
        bool bitVal  = getValueOfBit(var1, this->subByteConstant);
        for (int var2 = 0; var2 < this->byteLength; ++var2) {
            bitVal ^= this->subBytesMatrix[var1][var2] * getValueOfBit(var2, inverseByte);
        }
        newByte ^= (1 << var1) * bitVal;
    }
    return newByte;
}

uint8_t AES::decSubytesTransformationOnByte(uint8_t byte) {
    uint8_t byteWithOutConst = byte ^ this->subByteConstant;
    uint8_t invOriginalByte = 0;

    for (int var1 = 0; var1 < this->byteLength; ++var1) {
        bool bitVal  = 0;
        for (int var2 = 0; var2 < this->byteLength; ++var2) {
            bitVal ^= this->decSubBytesMatrix[var1][var2] * getValueOfBit(var2, byteWithOutConst);
        }
        invOriginalByte ^= (1 << var1) * bitVal;
    }
    return this->inverse[invOriginalByte];

}

stateType AES ::subBytesTransformationOnState(stateType state) {
    stateType newState;
    for (int var1 = 0; var1 < stateHeight; ++var1) {
        std :: vector<uint8_t> lineFromState;
        for (int var2 = 0; var2 < stateLength; ++var2) {
            lineFromState.push_back(this->subBytesTransformationOnByte(state[var1][var2]));
        }
        newState.push_back(lineFromState);
    }
    return newState;
}

stateType AES::decSubBytesTransfromationOnState(stateType state) {
    stateType newState;
    for (int var1 = 0; var1 < stateHeight; ++var1) {
        std :: vector<uint8_t> lineFromState;
        for (int var2 = 0; var2 < stateLength; ++var2) {
            lineFromState.push_back(this->decSubytesTransformationOnByte(state[var1][var2]));
        }
        newState.push_back(lineFromState);
    }
    return newState;
};

std :: vector<stateType> AES ::subBytesTransformation(std::vector<stateType> states) {
    std :: vector<stateType> newStates;
    for (int var = 0; var < states.size(); ++var) {
        newStates.push_back(subBytesTransformationOnState(states[var]));
    }
    return newStates;
}

stateType AES ::shiftRowsOnState(stateType state) {
    stateType newState;
        for (int var1 = 0; var1 < stateHeight; ++var1) {
            std :: vector<uint8_t> lineFromState;
            for (int var2 = 0; var2 < stateLength; ++var2) {
                lineFromState.push_back(state[var1][(var2 + var1) % stateLength]);
            }
            newState.push_back(lineFromState);
        }
    return newState;
}

stateType AES::decShiftRowsOnState(stateType state) {
    stateType newState;
    for (int var1 = 0; var1 < stateHeight; ++var1) {
        std :: vector<uint8_t> lineFromState;
        for (int var2 = 0; var2 < stateLength; ++var2) {
            int index = (var2 - var1) >= 0 ? var2 - var1 : stateLength + var2 - var1;
            lineFromState.push_back(state[var1][index]);
        }
        newState.push_back(lineFromState);
    }
    return newState;
}


std :: vector<stateType> AES ::shiftRowsTransformation(std::vector<stateType> states) {
    std :: vector<stateType> newStates;
    for (int var = 0; var < states.size(); ++var) {
        newStates.push_back(shiftRowsOnState(states[var]));
    }
    return newStates;
}

uint8_t AES :: prod2(uint8_t x) {
    uint8_t tmip = ((x & mb) > 0);
    uint8_t shiftByte = x << 1;
    return shiftByte ^ (sb * tmip);
}

uint8_t AES :: prod2k(uint8_t powerOf2, uint8_t el) {
    if(powerOf2 > 7 || powerOf2 < 0) {
        throwException("power is greater than 7 or less then 0, AES.cpp");
    }
    uint8_t result = el;
    for (int power = 0; power < powerOf2; ++power) {
        result = prod2(result);
    }
    return result;
}

uint8_t AES :: prod(uint8_t n, uint8_t m) {
    uint8_t product = 0;
    for (int var = 0; var < byteLength; ++var) {
        product ^= getValueOfBit(var, m)? prod2k(var, n) : 0;
    }
    return product;
}

std::vector<uint8_t> AES :: enMixColumn(std::vector<uint8_t> column) {

    if (column.size() != stateHeight) {
        throwException("size's column is different of stateHeight AES.cpp");
    }
    std :: vector<uint8_t> newColumn;
    for (int var1 = 0; var1 < stateHeight; ++var1) {
        uint8_t elValue = 0;
        for (int var2 = 0; var2 < stateHeight; ++var2) {
            elValue ^= prod(enMixColumnMat[var1][var2], column[var2]);
        }
        newColumn.push_back(elValue);
    }
    return newColumn;
}

std::vector<uint8_t> AES::decMixColumn(std::vector<uint8_t> column) {
    if (column.size() != stateHeight) {
        throwException("size's column is different of stateHeight AES.cpp");
    }
    std :: vector<uint8_t> newColumn;
    for (int var1 = 0; var1 < stateHeight; ++var1) {
        uint8_t elValue = 0;
        for (int var2 = 0; var2 < stateHeight; ++var2) {
            elValue ^= prod(decMixColumnMat[var1][var2], column[var2]);
        }
        newColumn.push_back(elValue);
    }
    return newColumn;
}

stateType AES::enMixColumnOnState(stateType state) {
    stateType newState = state;
    for (int var1 = 0; var1 < stateLength; ++var1) {
        std :: vector<uint8_t> column;
        for (int var2 = 0; var2 < stateHeight; ++var2) {
            column.push_back(state[var2][var1]);
        }
        std :: vector<uint8_t> newColumn = enMixColumn(column);
        for (int var2 = 0; var2 < stateHeight; ++var2) {
            newState[var2][var1] = newColumn[var2];
        }
    }
    return newState;
}

stateType AES::decMixColumnOnState(stateType state) {
    stateType newState = state;
    for (int var1 = 0; var1 < stateLength; ++var1) {
        std :: vector<uint8_t> column;
        for (int var2 = 0; var2 < stateHeight; ++var2) {
            column.push_back(state[var2][var1]);
        }
        std :: vector<uint8_t> newColumn = decMixColumn(column);
        for (int var2 = 0; var2 < stateHeight; ++var2) {
            newState[var2][var1] = newColumn[var2];
        }
    }
    return newState;
}

std::vector<stateType> AES :: mixColumnTransfromation(std::vector<stateType> states) {
    std::vector<stateType> newStates;
    for (int var = 0; var < states.size(); ++var) {
        newStates.push_back(enMixColumnOnState(states[var]));
    }
    return newStates;
}

stateType AES::generateKey(unsigned int seed) {
    srand(seed);
    stateType key;
    for (int var1 = 0; var1 < stateHeight; ++var1) {
        std :: vector<uint8_t> lineFromKey;
        for (int var2 = 0; var2 < keyLength; ++var2) {
            lineFromKey.push_back(rand() % 256);
        }
        key.push_back(lineFromKey);
    }
    this->lastKey = key;
    return key;
}

stateType AES::getLastKey() {
    return this->lastKey;
}

uint8_t AES::rotByte(uint8_t byte) {
    return ((mb & byte) > 0) + (byte << 1);
}

std::vector<uint8_t> AES::rotWord(std::vector<uint8_t> word) {
    if (word.size() != this->wordLength) throwException("Your input isn't a word");
    std :: vector<uint8_t> newWord;
    for (int var = 0; var < this->wordLength; ++var) {
        newWord.push_back(word[(var + 1) % wordLength]);
    }
    return newWord;
}

std::vector<uint8_t> AES::subWord(std::vector<uint8_t> word) {
    std::vector<uint8_t> newWord;
    if (word.size() != this->wordLength) throwException("Your input isn't a word");
    for (int var = 0; var < this->wordLength; ++var) {
        newWord.push_back(this->subBytesTransformationOnByte(word[var]));
    }
    return newWord;
}

std::vector<uint8_t> AES::getRcon(int i) {
    const int x_i = prod2k(i-1,1);
    std::vector<uint8_t> RconIWord;
    RconIWord.push_back(x_i);
    for (int var = 1; var < this->wordLength; ++var) {
        RconIWord.push_back(0);
    }
    return RconIWord;
}

std::vector<uint8_t> AES::sumWord(std::vector<uint8_t> word1, std::vector<uint8_t> word2) {
    if (word1.size() != this->wordLength || word2.size() != this->wordLength ) throwException("Your input isn't a word");
    std::vector<uint8_t> newWord;
    for (int var = 0; var < this->wordLength; ++var) {
        newWord.push_back(word1[var] ^ word2[var]);
    }
    return newWord;
}
stateType AES::tranState(stateType state) {
    stateType newState;
    int height = state.size();
    int length = state[0].size();
    for (int var1 = 0; var1 < length; ++var1) {
        std :: vector<uint8_t> lineFromNewState;
        for (int var2 = 0; var2 < height; ++var2) {
            lineFromNewState.push_back(state[var2][var1]);
        }
        newState.push_back(lineFromNewState);
    }
    return newState;
}

std :: vector<stateType> AES::expandsKey(stateType key) {
    if (key.size() != this->stateHeight) throwException("key hight isn't equal with standard height");
    if (key[0].size() != this->keyLength) throwException("Key doesn't have same length as AES standard key that have been setted at init");
    int requiredColumn = this->stateLength * (this->numberRounds + 1);
    std :: vector<std :: vector<uint8_t >> allColumnFromExpandsKey;
    for (int var1 = 0; var1 < this->keyLength; ++var1) {
        std :: vector<uint8_t> columnFromKey;
        for (int var2 = 0; var2 < this->stateHeight; ++var2) {
            columnFromKey.push_back(key[var2][var1]);
        }
        allColumnFromExpandsKey.push_back(columnFromKey);
    }
    for (int var1 = this->keyLength; var1 < requiredColumn; ++var1) {
        std::vector<uint8_t> temp = allColumnFromExpandsKey[var1-1];
        if (var1 % this->keyLength == 0) {
            std::vector<uint8_t> rconI = this->getRcon(var1/this->keyLength);
            temp = this->sumWord(this->subWord(this->rotWord(temp)), rconI);
        } else if (this->keyLength > 6 and var1 % this->keyLength == 4) {
            temp = this->subWord(temp);
        }
        allColumnFromExpandsKey.push_back(sumWord(allColumnFromExpandsKey[var1 - this->keyLength], temp));
    }
    std :: vector<stateType> keys;
    stateType keyState;
    for (int var1 = 0; var1 < requiredColumn; ++var1) {
        keyState.push_back(allColumnFromExpandsKey[var1]);
        if((var1 + 1) % this->stateLength == 0) {
            keys.push_back(tranState(keyState));
            keyState = stateType ();
        }
    }
    return keys;
}

stateType AES::addRoundKey(stateType state, stateType roundKey) {
    stateType newState;
    if(state.size() != stateHeight || roundKey.size() != stateHeight) throwException("state height  and roundKey height must be equal with stateHeight");
    if(state[0].size() != stateLength || roundKey[0].size() != stateLength) throwException("state length and roundKey length must be equal with stateLength");
    for (int var1 = 0; var1 < this->stateHeight; ++var1) {
        std::vector<uint8_t> newLineFromState;
        for(int var2 = 0; var2 < this->stateLength; ++var2) {
            newLineFromState.push_back(state[var1][var2] ^ roundKey[var1][var2]);
        }
        newState.push_back(newLineFromState);
    }
    return newState;
}

std :: vector<stateType> AES::addRoundKeyOnStates(std::vector<stateType> states , stateType roundKey) {
    std :: vector<stateType> newStates;
    for(int var = 0; var < states.size(); ++var) {
        newStates.push_back(this->addRoundKey(states[var], roundKey));
    }
    return newStates;
}

std::string AES::transformStatesIntoMessage(std :: vector<stateType> states) {
    std :: string message = "";
    for(int var1 = 0; var1 < states.size(); ++var1) {
        for(int var2 = 0; var2 < this->stateHeight; ++var2) {
            for(int var3 = 0; var3 < this->stateLength; ++var3) {
                message += (unsigned char)states[var1][var2][var3];
            }
        }
    }
    return message;
}
stateType AES::encryptState(stateType state, const std::vector<stateType> &keys) {
   // if (state.size() != this->stateLength || state[0].size()) throwException("state doesn't have standard dimension");
    stateType newState;
    newState = this->addRoundKey(state, keys[0]);
    for (int var = 1; var <= this->numberRounds - 1; ++var) {
        newState= this->subBytesTransformationOnState(newState);
        newState = this->shiftRowsOnState(newState);
        newState = this->enMixColumnOnState(newState);
        newState = this->addRoundKey(newState, keys[var]);
    }
    newState= this->subBytesTransformationOnState(newState);
    newState = this->shiftRowsOnState(newState);
    newState = this->addRoundKey(newState, keys[this->numberRounds]);
    return newState;
}

stateType AES::decryptState(stateType encryptState, const std :: vector<stateType> & keys) {
//    if (encryptState.size() != this->stateLength || encryptState[0].size()) throwException("state doesn't have standard dimension AES.cpp");
    //std::vector<stateType> keys = this->expandsKey(decryptKey);
    stateType originalState = this->addRoundKey(encryptState, keys[this->numberRounds]);
    originalState = this->decShiftRowsOnState(originalState);
    originalState = this->decSubBytesTransfromationOnState(originalState);
    for (int var = this->numberRounds - 1; var >= 1; --var) {
        originalState = this->addRoundKey(originalState, keys[var]);
        originalState = this->decMixColumnOnState(originalState);
        originalState = this->decShiftRowsOnState(originalState);
        originalState= this->decSubBytesTransfromationOnState(originalState);
    }
    originalState = this->addRoundKey(originalState, keys[0]);
    return originalState;
}
std::vector<stateType> AES::decStatesMessage(std::vector<stateType> encryptStatesMessage, stateType securityKey) {
    // de vazut ce se intampla cu mesajul null
    std::vector<stateType>blocksOfKeys = this->expandsKey(securityKey);
    std::vector<stateType>segmentsOfBlocks = encryptStatesMessage;
    int numberOfStates = segmentsOfBlocks.size() - 1;
    stateType ivState = segmentsOfBlocks[numberOfStates];
    std::vector<stateType> decStates;
    for (int var = 0; var < numberOfStates; ++var) decStates.push_back(segmentsOfBlocks[var]);
    int lengthOfSegment = numberOfStates/numberThreadsForDec;
    int numberOfIterations = [] (int k, int numberOfStates) {
        while (numberOfStates/k == 0) --k;
        return k;
    }(this->numberThreadsForDec, numberOfStates);
    std::vector<std::thread> allThreads;
    for (int var = 0; var < numberOfIterations; ++var) {
        const int st = var * (lengthOfSegment);
        const int dr = (var + 1) == numberOfIterations ? numberOfStates : (var + 1) * lengthOfSegment;
        allThreads.push_back(std::thread(&AES::decThreadFun, this, &decStates, segmentsOfBlocks, blocksOfKeys, st, dr, ivState));
    }
    for (auto &th : allThreads) {
        th.join();
    }
    return decStates;
}

void AES::decThreadFun(std::vector<stateType> * decStates, const std::vector<stateType> &segmentOfBlocks,
                       const std::vector<stateType> &blocksOfKeys, const int st, const int dr, const stateType &ivState) {
    for (int var = st; var < dr; ++var) {
        if (var == 0) {
            (*decStates)[var] = this->addRoundKey(this->decryptState(segmentOfBlocks[var], blocksOfKeys), ivState);
        } else {
            (*decStates)[var] = this->addRoundKey(this->decryptState(segmentOfBlocks[var], blocksOfKeys), segmentOfBlocks[var-1]);
        }
    }
}


void AES::setDecKey(stateType decKey) {
    this->decKey = decKey;
}

void AES::setNumberRounds(int numberRounds) {
    this->numberRounds = numberRounds;
}

void AES::setNumberThreadForDec(int numberThreadsForDec) {
    this->numberThreadsForDec = numberThreadsForDec;
}

std::string AES::decMessage(std::string encMessage) {
    if (encMessage.length() % 16) throwException("16 isn't a divizor for encMessage length");
    std::vector<uint8_t> bytesFromMessage;
    for (int var = 0; var < encMessage.length(); ++var) {
        bytesFromMessage.push_back((uint8_t)encMessage[var]);
    }
    std::vector<stateType> encStates = this->transformBytesInStates(bytesFromMessage);
    std::vector<stateType> decStates = this->decStatesMessage(encStates, this->decKey);
    std::vector<uint8_t> decBytes = this->transformStatesInBytes(decStates);
    std::string decMessage = this->transformBytesInMessage(decBytes, DECRYPTION);
    return decMessage;
}
stateType AES::generateIvState() {
    stateType ivState;
    srand(time(NULL));
    for (int var1 = 0; var1 < stateHeight; ++var1) {
        std::vector<uint8_t> lineFromState;
        for (int var2 = 0; var2 < stateLength; ++var2) {
            lineFromState.push_back(rand() % 256);
        }
        ivState.push_back(lineFromState);
    }
    return ivState;
}
std::string AES::encMessage(std::string message) {
    std::vector<stateType>states = this->transformMessageInStates(message);
    this->iVState = generateIvState();
    this->lastKey = generateKey();
    const std :: vector<stateType> keys = this->expandsKey(lastKey);
    std::vector<stateType>encStates;
    for (int var = 0; var < states.size(); ++var) {
        if (var == 0) {
            encStates.push_back(this->encryptState(this->addRoundKey(states[0], this->iVState), keys));
        } else {
            encStates.push_back(this->encryptState(this->addRoundKey(states[var], encStates[var-1]), keys));
        }
    }
    encStates.push_back(this->iVState);
    return this->transformStatesIntoMessage(encStates);
}

std::string AES::encMessage(std::string message, stateType key) {
    std::vector<stateType>states = this->transformMessageInStates(message);
    this->iVState = this->generateIvState();
    this->lastKey = key;
    const std :: vector<stateType> keys = this->expandsKey(lastKey);
    std::vector<stateType>encStates;
    for (int var = 0; var < states.size(); ++var) {
        if (var == 0) {
            encStates.push_back(this->encryptState(this->addRoundKey(states[0], this->iVState), keys));
        } else {
            encStates.push_back(this->encryptState(this->addRoundKey(states[var], encStates[var-1]), keys));
        }
    }
    encStates.push_back(this->iVState);
    return this->transformStatesIntoMessage(encStates);
}

