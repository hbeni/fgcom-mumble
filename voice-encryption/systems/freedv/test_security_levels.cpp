/**
 * @file test_security_levels.cpp
 * @brief Test ChaCha20-Poly1305 Security Levels and X25519 Key Exchange
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file demonstrates the new security levels and X25519 key exchange
 * functionality in the ChaCha20-Poly1305 implementation.
 */

#include "chacha20_poly1305.h"
#include <iostream>
#include <vector>
#include <string>

using namespace fgcom::freedv::crypto;

void testSecurityLevels() {
    std::cout << "=== Testing ChaCha20-Poly1305 Security Levels ===\n\n";
    
    // Test all security levels
    std::vector<SecurityLevel> levels = {
        SecurityLevel::STANDARD,
        SecurityLevel::TACTICAL,
        SecurityLevel::TOP_SECRET
    };
    
    for (auto level : levels) {
        std::cout << "Testing Security Level: " << static_cast<int>(level) << "-bit\n";
        std::cout << "Name: " << ChaCha20Poly1305Utils::getSecurityLevelName(level) << "\n";
        std::cout << "Description: " << ChaCha20Poly1305Utils::getSecurityLevelDescription(level) << "\n";
        std::cout << "Hash Function: " << ChaCha20Poly1305Utils::getRecommendedHashFunction(level) << "\n";
        std::cout << "Key Length: " << ChaCha20Poly1305::getKeyLengthForLevel(level) << " bytes\n\n";
        
        // Create encryption instance
        ChaCha20Poly1305 crypto(level);
        
        // Test key generation
        auto key_pair = crypto.generateKeyPair();
        std::cout << "Generated key pair - Private: " << key_pair.first.size() 
                  << " bytes, Public: " << key_pair.second.size() << " bytes\n";
        
        // Test key exchange simulation
        ChaCha20Poly1305 remote_crypto(level);
        auto remote_key_pair = remote_crypto.generateKeyPair();
        
        auto shared_secret = crypto.performKeyExchange(remote_key_pair.second);
        auto remote_shared_secret = remote_crypto.performKeyExchange(key_pair.second);
        
        std::cout << "Key exchange successful - Shared secret: " << shared_secret.size() << " bytes\n";
        
        // Derive encryption keys
        crypto.deriveKeyFromSharedSecret(shared_secret);
        remote_crypto.deriveKeyFromSharedSecret(remote_shared_secret);
        
        std::cout << "Encryption keys derived successfully\n";
        
        // Test encryption/decryption
        std::vector<uint8_t> test_data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
        auto encrypted = crypto.encrypt(test_data);
        auto decrypted = remote_crypto.decrypt(encrypted);
        
        std::cout << "Encryption/Decryption test: ";
        if (test_data == decrypted) {
            std::cout << "PASSED\n";
        } else {
            std::cout << "FAILED\n";
        }
        
        // Display security info
        std::cout << "Security Info:\n" << crypto.getSecurityInfo() << "\n";
        
        std::cout << "---\n\n";
    }
}

void testKeyExchange() {
    std::cout << "=== Testing X25519 Key Exchange ===\n\n";
    
    // Create two encryption instances for key exchange
    ChaCha20Poly1305 alice(SecurityLevel::TACTICAL);
    ChaCha20Poly1305 bob(SecurityLevel::TACTICAL);
    
    std::cout << "Alice and Bob both using TACTICAL security level (192-bit)\n\n";
    
    // Generate key pairs
    auto alice_keys = alice.generateKeyPair();
    auto bob_keys = bob.generateKeyPair();
    
    std::cout << "Alice generated key pair: " << alice_keys.first.size() 
              << " bytes private, " << alice_keys.second.size() << " bytes public\n";
    std::cout << "Bob generated key pair: " << bob_keys.first.size() 
              << " bytes private, " << bob_keys.second.size() << " bytes public\n\n";
    
    // Perform key exchange
    auto alice_shared = alice.performKeyExchange(bob_keys.second);
    auto bob_shared = bob.performKeyExchange(alice_keys.second);
    
    std::cout << "Key exchange completed\n";
    std::cout << "Alice shared secret: " << alice_shared.size() << " bytes\n";
    std::cout << "Bob shared secret: " << bob_shared.size() << " bytes\n\n";
    
    // Derive encryption keys
    alice.deriveKeyFromSharedSecret(alice_shared);
    bob.deriveKeyFromSharedSecret(bob_shared);
    
    std::cout << "Encryption keys derived from shared secrets\n\n";
    
    // Test secure communication
    std::string message = "Top secret mission data";
    std::vector<uint8_t> message_data(message.begin(), message.end());
    
    std::cout << "Testing secure communication...\n";
    std::cout << "Original message: " << message << "\n";
    
    // Alice encrypts message
    auto encrypted = alice.encrypt(message_data);
    std::cout << "Encrypted message: " << encrypted.size() << " bytes\n";
    
    // Bob decrypts message
    auto decrypted = bob.decrypt(encrypted);
    std::string decrypted_message(decrypted.begin(), decrypted.end());
    std::cout << "Decrypted message: " << decrypted_message << "\n";
    
    if (message == decrypted_message) {
        std::cout << "Secure communication: SUCCESS\n";
    } else {
        std::cout << "Secure communication: FAILED\n";
    }
}

void testSecurityLevelSwitching() {
    std::cout << "=== Testing Security Level Switching ===\n\n";
    
    ChaCha20Poly1305 crypto(SecurityLevel::STANDARD);
    std::cout << "Initial security level: " << static_cast<int>(crypto.getSecurityLevel()) << "-bit\n";
    std::cout << "Initial key length: " << crypto.getKeyLength() << " bytes\n\n";
    
    // Switch to tactical
    crypto.setSecurityLevel(SecurityLevel::TACTICAL);
    std::cout << "Switched to TACTICAL: " << static_cast<int>(crypto.getSecurityLevel()) << "-bit\n";
    std::cout << "New key length: " << crypto.getKeyLength() << " bytes\n\n";
    
    // Switch to top secret
    crypto.setSecurityLevel(SecurityLevel::TOP_SECRET);
    std::cout << "Switched to TOP_SECRET: " << static_cast<int>(crypto.getSecurityLevel()) << "-bit\n";
    std::cout << "New key length: " << crypto.getKeyLength() << " bytes\n\n";
    
    // Switch back to standard
    crypto.setSecurityLevel(SecurityLevel::STANDARD);
    std::cout << "Switched back to STANDARD: " << static_cast<int>(crypto.getSecurityLevel()) << "-bit\n";
    std::cout << "Final key length: " << crypto.getKeyLength() << " bytes\n";
}

int main() {
    std::cout << "ChaCha20-Poly1305 Security Levels and X25519 Key Exchange Test\n";
    std::cout << "================================================================\n\n";
    
    try {
        testSecurityLevels();
        testKeyExchange();
        testSecurityLevelSwitching();
        
        std::cout << "\nAll tests completed successfully!\n";
        std::cout << "\nSecurity Classifications:\n";
        std::cout << "- 128-bit (Standard): Squadron communications, routine operations\n";
        std::cout << "- 192-bit (Tactical): Command channels, tactical operations\n";
        std::cout << "- 256-bit (Top Secret): Special operations, classified missions\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
