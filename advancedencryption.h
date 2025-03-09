#ifndef ADVANCEDENCRYPTION_H
#define ADVANCEDENCRYPTION_H

#include <vector>
#include <string>
#include <stdexcept>
#include <random>
#include <algorithm>
#include <limits>

class AdvancedEncryption {
private:
    // Key structure
    struct EncryptionKey {
        std::vector<uint8_t> primaryKey;
        std::vector<uint8_t> secondaryKey;
        std::vector<uint8_t> substitutionBox;
        std::vector<uint8_t> inverseSubstitutionBox;
        std::vector<uint8_t> permutationTable;
        std::vector<uint8_t> inversePermutationTable;
        std::vector<uint32_t> roundConstants;
    };

    EncryptionKey key;
    static const int BLOCK_SIZE = 16; // 128 bits
    static const int NUM_ROUNDS = 16;
    static const int KEY_SIZE = 32;   // 256 bits

    void initializeKey(const std::vector<uint8_t>& userKey);
    void substitute(std::vector<uint8_t>& block);
    void inverseSubstitute(std::vector<uint8_t>& block);
    std::vector<uint8_t> permute(const std::vector<uint8_t>& block);
    std::vector<uint8_t> inversePermute(const std::vector<uint8_t>& block);
    void mix(std::vector<uint8_t>& block, uint32_t roundConstant);
    void inverseMix(std::vector<uint8_t>& block, uint32_t roundConstant);
    std::vector<uint8_t> padInput(const std::vector<uint8_t>& input);
    std::vector<uint8_t> removePadding(const std::vector<uint8_t>& paddedInput);

public:
    AdvancedEncryption() {}

    void setKey(const std::vector<uint8_t>& userKey);
    std::vector<uint8_t> encryptBlock(const std::vector<uint8_t>& block);
    std::vector<uint8_t> decryptBlock(const std::vector<uint8_t>& block);
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);

    // Helper functions
    static std::vector<uint8_t> stringToBytes(const std::string& str);
    static std::string bytesToString(const std::vector<uint8_t>& bytes);
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);
    static std::vector<uint8_t> hexToBytes(const std::string& hex);
};

#endif // ADVANCEDENCRYPTION_H
