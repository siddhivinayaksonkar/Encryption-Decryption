#include "advancedencryption.h"
#include <cstring>
#include <stdexcept>

void AdvancedEncryption::initializeKey(const std::vector<uint8_t>& userKey) {
    if (userKey.size() != KEY_SIZE) {
        throw std::invalid_argument("Invalid key size");
    }

    // Initialize primary and secondary keys
    key.primaryKey = userKey;
    key.secondaryKey.resize(KEY_SIZE);
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        key.secondaryKey[i] = userKey[i] ^ 0x36;  // XOR with padding
    }

    // Initialize substitution boxes
    key.substitutionBox.resize(256);
    key.inverseSubstitutionBox.resize(256);
    for (int i = 0; i < 256; ++i) {
        key.substitutionBox[i] = i;
    }

    // Create a pseudo-random permutation using the key
    std::mt19937 rng(std::hash<std::string>{}(std::string(userKey.begin(), userKey.end())));
    std::shuffle(key.substitutionBox.begin(), key.substitutionBox.end(), rng);

    // Create inverse substitution box
    for (int i = 0; i < 256; ++i) {
        key.inverseSubstitutionBox[key.substitutionBox[i]] = i;
    }

    // Initialize permutation tables
    key.permutationTable.resize(BLOCK_SIZE);
    key.inversePermutationTable.resize(BLOCK_SIZE);
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        key.permutationTable[i] = i;
    }
    std::shuffle(key.permutationTable.begin(), key.permutationTable.end(), rng);

    // Create inverse permutation table
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        key.inversePermutationTable[key.permutationTable[i]] = i;
    }

    // Generate round constants
    key.roundConstants.resize(NUM_ROUNDS);
    for (int i = 0; i < NUM_ROUNDS; ++i) {
        key.roundConstants[i] = rng();
    }
}

void AdvancedEncryption::setKey(const std::vector<uint8_t>& userKey) {
    initializeKey(userKey);
}

void AdvancedEncryption::substitute(std::vector<uint8_t>& block) {
    for (auto& byte : block) {
        byte = key.substitutionBox[byte];
    }
}

void AdvancedEncryption::inverseSubstitute(std::vector<uint8_t>& block) {
    for (auto& byte : block) {
        byte = key.inverseSubstitutionBox[byte];
    }
}

std::vector<uint8_t> AdvancedEncryption::permute(const std::vector<uint8_t>& block) {
    std::vector<uint8_t> result(BLOCK_SIZE);
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        result[key.permutationTable[i]] = block[i];
    }
    return result;
}

std::vector<uint8_t> AdvancedEncryption::inversePermute(const std::vector<uint8_t>& block) {
    std::vector<uint8_t> result(BLOCK_SIZE);
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        result[key.inversePermutationTable[i]] = block[i];
    }
    return result;
}

void AdvancedEncryption::mix(std::vector<uint8_t>& block, uint32_t roundConstant) {
    for (size_t i = 0; i < block.size(); ++i) {
        block[i] ^= (roundConstant >> (i % 32)) & 0xFF;
        if (i > 0) {
            block[i] ^= block[i - 1];
        }
    }
}

void AdvancedEncryption::inverseMix(std::vector<uint8_t>& block, uint32_t roundConstant) {
    for (int i = block.size() - 1; i >= 0; --i) {
        if (i > 0) {
            block[i] ^= block[i - 1];
        }
        block[i] ^= (roundConstant >> (i % 32)) & 0xFF;
    }
}

std::vector<uint8_t> AdvancedEncryption::padInput(const std::vector<uint8_t>& input) {
    size_t paddingSize = BLOCK_SIZE - (input.size() % BLOCK_SIZE);
    std::vector<uint8_t> padded = input;
    padded.resize(input.size() + paddingSize, static_cast<uint8_t>(paddingSize));
    return padded;
}

std::vector<uint8_t> AdvancedEncryption::removePadding(const std::vector<uint8_t>& paddedInput) {
    if (paddedInput.empty()) {
        throw std::runtime_error("Empty input");
    }
    
    uint8_t paddingSize = paddedInput.back();
    if (paddingSize > BLOCK_SIZE || paddingSize > paddedInput.size()) {
        throw std::runtime_error("Invalid padding");
    }
    
    return std::vector<uint8_t>(paddedInput.begin(), paddedInput.end() - paddingSize);
}

std::vector<uint8_t> AdvancedEncryption::encryptBlock(const std::vector<uint8_t>& block) {
    if (block.size() != BLOCK_SIZE) {
        throw std::invalid_argument("Invalid block size");
    }

    std::vector<uint8_t> state = block;
    
    // Initial key mixing
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        state[i] ^= key.primaryKey[i % KEY_SIZE];
    }

    // Main encryption rounds
    for (int round = 0; round < NUM_ROUNDS; ++round) {
        substitute(state);
        state = permute(state);
        mix(state, key.roundConstants[round]);
    }

    // Final key mixing
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        state[i] ^= key.secondaryKey[i % KEY_SIZE];
    }

    return state;
}

std::vector<uint8_t> AdvancedEncryption::decryptBlock(const std::vector<uint8_t>& block) {
    if (block.size() != BLOCK_SIZE) {
        throw std::invalid_argument("Invalid block size");
    }

    std::vector<uint8_t> state = block;

    // Reverse final key mixing
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        state[i] ^= key.secondaryKey[i % KEY_SIZE];
    }

    // Main decryption rounds
    for (int round = NUM_ROUNDS - 1; round >= 0; --round) {
        inverseMix(state, key.roundConstants[round]);
        state = inversePermute(state);
        inverseSubstitute(state);
    }

    // Reverse initial key mixing
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        state[i] ^= key.primaryKey[i % KEY_SIZE];
    }

    return state;
}

std::vector<uint8_t> AdvancedEncryption::encrypt(const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> padded = padInput(plaintext);
    std::vector<uint8_t> ciphertext;

    // Process each block
    for (size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
        std::vector<uint8_t> block(padded.begin() + i, padded.begin() + i + BLOCK_SIZE);
        auto encryptedBlock = encryptBlock(block);
        ciphertext.insert(ciphertext.end(), encryptedBlock.begin(), encryptedBlock.end());
    }

    return ciphertext;
}

std::vector<uint8_t> AdvancedEncryption::decrypt(const std::vector<uint8_t>& ciphertext) {
    if (ciphertext.size() % BLOCK_SIZE != 0) {
        throw std::invalid_argument("Invalid ciphertext size");
    }

    std::vector<uint8_t> decrypted;

    // Process each block
    for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE) {
        std::vector<uint8_t> block(ciphertext.begin() + i, ciphertext.begin() + i + BLOCK_SIZE);
        auto decryptedBlock = decryptBlock(block);
        decrypted.insert(decrypted.end(), decryptedBlock.begin(), decryptedBlock.end());
    }

    // Remove padding
    return removePadding(decrypted);
}

std::vector<uint8_t> AdvancedEncryption::stringToBytes(const std::string &str)
{
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string AdvancedEncryption::bytesToString(const std::vector<uint8_t> &bytes)
{
    return std::string(bytes.begin(), bytes.end());
}

std::string AdvancedEncryption::bytesToHex(const std::vector<uint8_t> &bytes)
{
    static const char hexChars[] = "0123456789ABCDEF";
    std::string hex;
    for (uint8_t b : bytes) {
        hex.push_back(hexChars[b >> 4]);
        hex.push_back(hexChars[b & 0x0F]);
    }
    return hex;
}

std::vector<uint8_t> AdvancedEncryption::hexToBytes(const std::string &hex)
{
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}
