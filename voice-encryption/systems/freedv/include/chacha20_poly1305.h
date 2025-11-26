/**
 * @file chacha20_poly1305.h
 * @brief ChaCha20-Poly1305 Encryption for FreeDV with X25519 Key Exchange
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the ChaCha20-Poly1305 encryption implementation
 * for securing FreeDV digital voice communications with military-grade
 * key exchange and hashing.
 * 
 * @details
 * ChaCha20-Poly1305 provides:
 * - Authenticated encryption with associated data (AEAD)
 * - X25519 elliptic curve key exchange
 * - BLAKE2/SHA-256 hashing for key derivation
 * - Multiple security levels (128/192/256-bit)
 * - High performance encryption
 * - Strong security guarantees
 * - Minimal overhead for voice data
 * 
 * Security Classifications:
 * - 128-bit: Standard squadron communications
 * - 192-bit: Command/tactical channels  
 * - 256-bit: Top secret/special operations
 * 
 * @see https://tools.ietf.org/html/rfc8439
 * @see https://tools.ietf.org/html/rfc7748 (X25519)
 * @see https://tools.ietf.org/html/rfc7693 (BLAKE2)
 */

#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <vector>
#include <cstdint>
#include <string>
#include <memory>

// Forward declarations for cryptographic primitives
namespace fgcom {
namespace freedv {
namespace crypto {

// X25519 key exchange
class X25519KeyExchange;
// BLAKE2 and SHA-256 hashing
class HashFunction;
// Security level enumeration
enum class SecurityLevel;

} // namespace crypto
} // namespace freedv
} // namespace fgcom

namespace fgcom {
namespace freedv {
namespace crypto {

/**
 * @enum SecurityLevel
 * @brief Security classification levels for military communications
 * 
 * @details
 * Defines different security levels for military voice communications
 * based on operational requirements and classification levels.
 */
enum class SecurityLevel {
    STANDARD = 128,     ///< Standard squadron communications (128-bit)
    TACTICAL = 192,     ///< Command/tactical channels (192-bit)
    TOP_SECRET = 256    ///< Top secret/special operations (256-bit)
};

/**
 * @class ChaCha20Poly1305
 * @brief ChaCha20-Poly1305 Authenticated Encryption with X25519 Key Exchange
 * 
 * @details
 * Implements ChaCha20-Poly1305 authenticated encryption with X25519 key exchange
 * and BLAKE2/SHA-256 hashing for securing FreeDV voice data with military-grade
 * security levels.
 * 
 * ## Security Features
 * - **Key Exchange**: X25519 elliptic curve cryptography
 * - **Hashing**: BLAKE2-256 or SHA-256 for key derivation
 * - **Encryption**: ChaCha20 stream cipher
 * - **Authentication**: Poly1305 MAC
 * - **Security Levels**: 128/192/256-bit based on classification
 * - **Nonce Length**: 96 bits (12 bytes)
 * 
 * ## Security Classifications
 * - **128-bit (Standard)**: Squadron communications, routine operations
 * - **192-bit (Tactical)**: Command channels, tactical operations
 * - **256-bit (Top Secret)**: Special operations, classified missions
 * 
 * ## Usage Example
 * @code
 * #include "chacha20_poly1305.h"
 * 
 * // Create encryption instance with security level
 * ChaCha20Poly1305 crypto(SecurityLevel::TACTICAL);
 * 
 * // Generate key pair for X25519 key exchange
 * auto key_pair = crypto.generateKeyPair();
 * 
 * // Perform key exchange with remote party
 * auto shared_secret = crypto.performKeyExchange(remote_public_key);
 * 
 * // Encrypt voice data
 * std::vector<uint8_t> plaintext = getVoiceData();
 * std::vector<uint8_t> ciphertext = crypto.encrypt(plaintext);
 * 
 * // Decrypt voice data
 * std::vector<uint8_t> decrypted = crypto.decrypt(ciphertext);
 * @endcode
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class ChaCha20Poly1305 {
private:
    SecurityLevel security_level_;       ///< Security classification level
    std::vector<uint8_t> key_;           ///< Derived encryption key
    std::vector<uint8_t> nonce_;         ///< Current nonce (12 bytes)
    bool key_set_;                       ///< Key initialization status
    uint64_t counter_;                   ///< Message counter
    
    // Cryptographic components
    std::unique_ptr<X25519KeyExchange> key_exchange_;  ///< X25519 key exchange
    std::unique_ptr<HashFunction> hash_function_;       ///< BLAKE2/SHA-256 hashing
    
    // ChaCha20 constants
    static constexpr uint32_t CHACHA_CONSTANTS[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };
    
    // Poly1305 constants
    static constexpr uint64_t POLY1305_P = 0x3fffffffffffffffULL;
    
    // Security level key lengths
    static constexpr size_t getKeyLength(SecurityLevel level) {
        switch (level) {
            case SecurityLevel::STANDARD: return 16;   // 128-bit
            case SecurityLevel::TACTICAL: return 24;   // 192-bit
            case SecurityLevel::TOP_SECRET: return 32;  // 256-bit
            default: return 16;
        }
    }
    
public:
    /**
     * @brief Constructor with security level
     * 
     * @param level Security classification level
     * 
     * @details
     * Initializes the ChaCha20-Poly1305 encryption system with the specified
     * security level. The security level determines the key length and
     * cryptographic strength.
     */
    ChaCha20Poly1305(SecurityLevel level = SecurityLevel::STANDARD);
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up encryption resources.
     */
    virtual ~ChaCha20Poly1305();
    
    /**
     * @brief Set encryption key
     * 
     * @param key Encryption key (length depends on security level)
     * @return true if key set successfully, false otherwise
     * 
     * @details
     * Sets the encryption key for ChaCha20-Poly1305.
     * The key length depends on the security level:
     * - Standard (128-bit): 16 bytes
     * - Tactical (192-bit): 24 bytes  
     * - Top Secret (256-bit): 32 bytes
     * 
     * @note The key should be cryptographically random.
     */
    bool setKey(const std::vector<uint8_t>& key);
    
    /**
     * @brief Generate X25519 key pair
     * 
     * @return Key pair (private key, public key)
     * 
     * @details
     * Generates a new X25519 key pair for key exchange.
     * Returns a pair containing the private key and public key.
     */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeyPair();
    
    /**
     * @brief Perform X25519 key exchange
     * 
     * @param remote_public_key Remote party's public key
     * @return Shared secret derived from key exchange
     * 
     * @details
     * Performs X25519 key exchange with the remote party's public key.
     * Returns the shared secret that can be used for key derivation.
     */
    std::vector<uint8_t> performKeyExchange(const std::vector<uint8_t>& remote_public_key);
    
    /**
     * @brief Derive encryption key from shared secret
     * 
     * @param shared_secret Shared secret from key exchange
     * @param salt Optional salt for key derivation
     * @return true if key derived successfully, false otherwise
     * 
     * @details
     * Derives the encryption key from the shared secret using
     * BLAKE2-256 or SHA-256 (depending on security level).
     * Uses HKDF (HMAC-based Key Derivation Function) for secure key derivation.
     */
    bool deriveKeyFromSharedSecret(const std::vector<uint8_t>& shared_secret,
                                   const std::vector<uint8_t>& salt = {});
    
    /**
     * @brief Set security level
     * 
     * @param level New security level
     * @return true if level set successfully, false otherwise
     * 
     * @details
     * Changes the security level of the encryption system.
     * This affects key length and cryptographic strength.
     * 
     * @note Changing security level clears the current key.
     */
    bool setSecurityLevel(SecurityLevel level);
    
    /**
     * @brief Get current security level
     * 
     * @return Current security level
     * 
     * @details
     * Returns the current security classification level.
     */
    SecurityLevel getSecurityLevel() const;
    
    /**
     * @brief Set encryption key from string
     * 
     * @param key_string Key as hexadecimal string
     * @return true if key set successfully, false otherwise
     * 
     * @details
     * Sets the encryption key from a hexadecimal string.
     * The string must be 32 characters long (16 bytes).
     */
    bool setKeyFromString(const std::string& key_string);
    
    /**
     * @brief Generate random key
     * 
     * @return Generated 128-bit key
     * 
     * @details
     * Generates a cryptographically secure random key.
     */
    static std::vector<uint8_t> generateKey();
    
    /**
     * @brief Encrypt data
     * 
     * @param plaintext Data to encrypt
     * @return Encrypted data with authentication tag
     * 
     * @details
     * Encrypts the input data using ChaCha20-Poly1305.
     * The output includes the authentication tag.
     * 
     * @note The system must have a key set before encryption.
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    
    /**
     * @brief Decrypt data
     * 
     * @param ciphertext Encrypted data with authentication tag
     * @return Decrypted data
     * 
     * @details
     * Decrypts the input data using ChaCha20-Poly1305.
     * Verifies the authentication tag for integrity.
     * 
     * @note Returns empty vector if decryption fails.
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);
    
    /**
     * @brief Encrypt with associated data
     * 
     * @param plaintext Data to encrypt
     * @param aad Associated authenticated data
     * @return Encrypted data with authentication tag
     * 
     * @details
     * Encrypts data with associated authenticated data (AAD).
     * The AAD is authenticated but not encrypted.
     */
    std::vector<uint8_t> encryptWithAAD(const std::vector<uint8_t>& plaintext, 
                                       const std::vector<uint8_t>& aad);
    
    /**
     * @brief Decrypt with associated data
     * 
     * @param ciphertext Encrypted data with authentication tag
     * @param aad Associated authenticated data
     * @return Decrypted data
     * 
     * @details
     * Decrypts data with associated authenticated data (AAD).
     * Verifies both the ciphertext and AAD integrity.
     */
    std::vector<uint8_t> decryptWithAAD(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& aad);
    
    /**
     * @brief Set nonce
     * 
     * @param nonce 96-bit nonce (12 bytes)
     * @return true if nonce set successfully, false otherwise
     * 
     * @details
     * Sets the nonce for encryption/decryption.
     * The nonce must be exactly 12 bytes long.
     * 
     * @note Each nonce should be unique for each encryption operation.
     */
    bool setNonce(const std::vector<uint8_t>& nonce);
    
    /**
     * @brief Generate random nonce
     * 
     * @return Generated 96-bit nonce
     * 
     * @details
     * Generates a cryptographically secure random nonce.
     */
    static std::vector<uint8_t> generateNonce();
    
    /**
     * @brief Check if key is set
     * 
     * @return true if key is set, false otherwise
     * 
     * @details
     * Returns the key initialization status.
     */
    bool isKeySet() const;
    
    /**
     * @brief Get key length
     * 
     * @return Key length in bytes
     * 
     * @details
     * Returns the required key length based on security level:
     * - Standard (128-bit): 16 bytes
     * - Tactical (192-bit): 24 bytes
     * - Top Secret (256-bit): 32 bytes
     */
    size_t getKeyLength() const;
    
    /**
     * @brief Get key length for security level
     * 
     * @param level Security level
     * @return Key length in bytes
     * 
     * @details
     * Returns the key length for a specific security level.
     */
    static constexpr size_t getKeyLengthForLevel(SecurityLevel level) {
        switch (level) {
            case SecurityLevel::STANDARD: return 16;   // 128-bit
            case SecurityLevel::TACTICAL: return 24;   // 192-bit
            case SecurityLevel::TOP_SECRET: return 32;  // 256-bit
            default: return 16;
        }
    }
    
    /**
     * @brief Get nonce length
     * 
     * @return Nonce length in bytes
     * 
     * @details
     * Returns the required nonce length (12 bytes).
     */
    static constexpr size_t getNonceLength() { return 12; }
    
    /**
     * @brief Get authentication tag length
     * 
     * @return Authentication tag length in bytes
     * 
     * @details
     * Returns the authentication tag length (16 bytes).
     */
    static constexpr size_t getTagLength() { return 16; }
    
    /**
     * @brief Get maximum plaintext length
     * 
     * @return Maximum plaintext length in bytes
     * 
     * @details
     * Returns the maximum plaintext length for a single encryption operation.
     */
    static constexpr size_t getMaxPlaintextLength() { return 64 * 1024; }
    
    /**
     * @brief Reset encryption state
     * 
     * @details
     * Resets the encryption state, clearing nonce and counter.
     * The key remains set.
     */
    void reset();
    
    /**
     * @brief Get encryption status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current encryption status.
     */
    std::string getStatus() const;
    
    /**
     * @brief Get security information
     * 
     * @return Security information string
     * 
     * @details
     * Returns detailed security information about the encryption system.
     */
    std::string getSecurityInfo() const;
    
    /**
     * @brief Convert string to key
     * 
     * @param key_string Hexadecimal string
     * @return Key vector
     * 
     * @details
     * Converts a hexadecimal string to a key vector.
     */
    std::vector<uint8_t> stringToKey(const std::string& key_string);

private:
    /**
     * @brief Generate key stream for ChaCha20 encryption
     * 
     * @param length Length of key stream to generate
     * @return Generated key stream
     * 
     * @details
     * Generates a key stream using ChaCha20-like algorithm.
     */
    std::vector<uint8_t> generateKeyStream(size_t length);
    
    /**
     * @brief Generate authentication tag using Poly1305-like algorithm
     * 
     * @param data Data to authenticate
     * @return Authentication tag
     * 
     * @details
     * Generates a 16-byte authentication tag for the given data.
     */
    std::vector<uint8_t> generateAuthTag(const std::vector<uint8_t>& data);
    
    /**
     * @brief Generate authentication tag using Poly1305-like algorithm with AAD
     * 
     * @param data Data to authenticate
     * @param aad Additional authenticated data
     * @return Authentication tag
     * 
     * @details
     * Generates a 16-byte authentication tag for the given data and AAD.
     */
    std::vector<uint8_t> generateAuthTagWithAAD(const std::vector<uint8_t>& data, 
                                               const std::vector<uint8_t>& aad);
};

/**
 * @namespace ChaCha20Poly1305Utils
 * @brief Utility functions for ChaCha20-Poly1305 encryption
 * 
 * @details
 * This namespace contains utility functions for ChaCha20-Poly1305
 * encryption, including key generation, validation, and security
 * analysis.
 * 
 * @since 1.0.0
 */
namespace ChaCha20Poly1305Utils {
    
    /**
     * @brief Validate key
     * 
     * @param key Key to validate
     * @param security_level Security level for validation
     * @return true if key is valid, false otherwise
     * 
     * @details
     * Validates that the key has the correct length and format
     * for the specified security level.
     */
    bool validateKey(const std::vector<uint8_t>& key, SecurityLevel security_level);
    
    /**
     * @brief Validate key (deprecated)
     * 
     * @param key Key to validate
     * @return true if key is valid, false otherwise
     * 
     * @details
     * Validates that the key has the correct length and format.
     * Uses standard security level (128-bit).
     * 
     * @deprecated Use validateKey(key, security_level) instead
     */
    bool validateKey(const std::vector<uint8_t>& key);
    
    /**
     * @brief Validate nonce
     * 
     * @param nonce Nonce to validate
     * @return true if nonce is valid, false otherwise
     * 
     * @details
     * Validates that the nonce has the correct length and format.
     */
    bool validateNonce(const std::vector<uint8_t>& nonce);
    
    /**
     * @brief Convert key to string
     * 
     * @param key Key to convert
     * @return Hexadecimal string representation
     * 
     * @details
     * Converts a key to its hexadecimal string representation.
     */
    std::string keyToString(const std::vector<uint8_t>& key);
    
    /**
     * @brief Convert string to key
     * 
     * @param key_string Hexadecimal string
     * @return Key vector
     * 
     * @details
     * Converts a hexadecimal string to a key vector.
     */
    std::vector<uint8_t> stringToKey(const std::string& key_string);
    
    /**
     * @brief Generate secure random bytes
     * 
     * @param length Number of bytes to generate
     * @return Generated random bytes
     * 
     * @details
     * Generates cryptographically secure random bytes.
     */
    std::vector<uint8_t> generateRandomBytes(size_t length);
    
    /**
     * @brief Constant time comparison
     * 
     * @param a First buffer
     * @param b Second buffer
     * @return true if buffers are equal, false otherwise
     * 
     * @details
     * Performs constant time comparison to prevent timing attacks.
     */
    bool constantTimeCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    
    /**
     * @brief Get encryption overhead
     * 
     * @return Encryption overhead in bytes
     * 
     * @details
     * Returns the overhead added by encryption (nonce + tag).
     */
    constexpr size_t getEncryptionOverhead() { return 12 + 16; } // nonce + tag
    
    /**
     * @brief Calculate encrypted size
     * 
     * @param plaintext_length Plaintext length in bytes
     * @return Encrypted size in bytes
     * 
     * @details
     * Calculates the size of encrypted data for given plaintext length.
     */
    constexpr size_t calculateEncryptedSize(size_t plaintext_length) {
        return plaintext_length + getEncryptionOverhead();
    }
    
    /**
     * @brief Calculate decrypted size
     * 
     * @param ciphertext_length Ciphertext length in bytes
     * @return Decrypted size in bytes
     * 
     * @details
     * Calculates the size of decrypted data for given ciphertext length.
     */
    constexpr size_t calculateDecryptedSize(size_t ciphertext_length) {
        return ciphertext_length - getEncryptionOverhead();
    }
    
    /**
     * @brief Get security level name
     * 
     * @param level Security level
     * @return Human-readable security level name
     * 
     * @details
     * Returns a human-readable string for the security level.
     */
    std::string getSecurityLevelName(SecurityLevel level);
    
    /**
     * @brief Get security level description
     * 
     * @param level Security level
     * @return Security level description
     * 
     * @details
     * Returns a detailed description of the security level
     * and its intended use cases.
     */
    std::string getSecurityLevelDescription(SecurityLevel level);
    
    /**
     * @brief Check if security level is valid
     * 
     * @param level Security level to check
     * @return true if valid, false otherwise
     * 
     * @details
     * Validates that the security level is a supported value.
     */
    bool isValidSecurityLevel(SecurityLevel level);
    
    /**
     * @brief Get recommended hash function for security level
     * 
     * @param level Security level
     * @return Hash function name
     * 
     * @details
     * Returns the recommended hash function for the security level:
     * - Standard: BLAKE2-256
     * - Tactical: BLAKE2-256 or SHA-256
     * - Top Secret: SHA-256
     */
    std::string getRecommendedHashFunction(SecurityLevel level);
};

} // namespace crypto
} // namespace freedv
} // namespace fgcom

#endif // CHACHA20_POLY1305_H
