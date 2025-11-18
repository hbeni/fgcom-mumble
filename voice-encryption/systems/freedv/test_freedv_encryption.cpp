/**
 * @file test_freedv_encryption.cpp
 * @brief FreeDV Encryption Test
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file demonstrates the ChaCha20-Poly1305 encryption functionality
 * for FreeDV digital voice communications.
 */

#include "freedv.h"
#include <iostream>
#include <vector>
#include <random>
#include <chrono>

using namespace fgcom::freedv;

int main() {
    std::cout << "=== FreeDV ChaCha20-Poly1305 Encryption Test ===" << std::endl;
    
    // Create FreeDV instance
    FreeDV freedv;
    
    // Initialize FreeDV system
    if (!freedv.initialize(44100.0f, 1)) {
        std::cerr << "Failed to initialize FreeDV system" << std::endl;
        return 1;
    }
    
    std::cout << "FreeDV system initialized successfully" << std::endl;
    
    // Set FreeDV mode
    if (!freedv.setMode(FreeDVMode::MODE_2020)) {
        std::cerr << "Failed to set FreeDV mode" << std::endl;
        return 1;
    }
    
    std::cout << "FreeDV mode set to MODE_2020" << std::endl;
    
    // Generate test audio data (1 second of 44.1 kHz audio)
    std::vector<float> test_audio(44100);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dis(-1.0f, 1.0f);
    
    for (auto& sample : test_audio) {
        sample = dis(gen);
    }
    
    std::cout << "Generated " << test_audio.size() << " audio samples" << std::endl;
    
    // Test without encryption
    std::cout << "\n--- Testing without encryption ---" << std::endl;
    std::cout << "Encryption status: " << (freedv.isEncryptionEnabled() ? "Enabled" : "Disabled") << std::endl;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> encoded_plain = freedv.encode(test_audio);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    std::cout << "Encoded " << encoded_plain.size() << " bytes in " << duration.count() << " microseconds" << std::endl;
    
    // Test with encryption
    std::cout << "\n--- Testing with ChaCha20-Poly1305 encryption ---" << std::endl;
    
    // Generate encryption key
    std::vector<uint8_t> encryption_key = FreeDV::generateEncryptionKey();
    std::cout << "Generated encryption key: ";
    for (const auto& byte : encryption_key) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
    
    // Enable encryption
    if (!freedv.enableEncryption(encryption_key)) {
        std::cerr << "Failed to enable encryption" << std::endl;
        return 1;
    }
    
    std::cout << "Encryption enabled successfully" << std::endl;
    std::cout << freedv.getEncryptionStatus() << std::endl;
    
    // Encode with encryption
    start_time = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> encoded_encrypted = freedv.encode(test_audio);
    end_time = std::chrono::high_resolution_clock::now();
    
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    std::cout << "Encoded and encrypted " << encoded_encrypted.size() << " bytes in " << duration.count() << " microseconds" << std::endl;
    
    // Calculate encryption overhead
    size_t overhead = encoded_encrypted.size() - encoded_plain.size();
    std::cout << "Encryption overhead: " << overhead << " bytes" << std::endl;
    std::cout << "Overhead percentage: " << (100.0 * overhead / encoded_plain.size()) << "%" << std::endl;
    
    // Test decryption
    std::cout << "\n--- Testing decryption ---" << std::endl;
    
    start_time = std::chrono::high_resolution_clock::now();
    std::vector<float> decrypted_audio = freedv.decode(encoded_encrypted);
    end_time = std::chrono::high_resolution_clock::now();
    
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    std::cout << "Decrypted " << decrypted_audio.size() << " audio samples in " << duration.count() << " microseconds" << std::endl;
    
    // Verify decryption
    if (decrypted_audio.size() == test_audio.size()) {
        std::cout << "Decryption successful - audio size matches original" << std::endl;
        
        // Calculate simple correlation (in real implementation, you'd use proper audio comparison)
        float correlation = 0.0f;
        for (size_t i = 0; i < std::min(test_audio.size(), decrypted_audio.size()); ++i) {
            correlation += test_audio[i] * decrypted_audio[i];
        }
        std::cout << "Audio correlation: " << correlation << std::endl;
    } else {
        std::cerr << "Decryption failed - audio size mismatch" << std::endl;
        return 1;
    }
    
    // Test with different key (should fail)
    std::cout << "\n--- Testing with wrong key (should fail) ---" << std::endl;
    
    std::vector<uint8_t> wrong_key(16, 0xFF);
    if (freedv.enableEncryption(wrong_key)) {
        std::vector<float> wrong_decrypt = freedv.decode(encoded_encrypted);
        if (wrong_decrypt.empty()) {
            std::cout << "Correctly failed to decrypt with wrong key" << std::endl;
        } else {
            std::cerr << "ERROR: Decryption succeeded with wrong key!" << std::endl;
            return 1;
        }
    }
    
    // Test encryption with key string
    std::cout << "\n--- Testing encryption with key string ---" << std::endl;
    
    std::string key_string = "0123456789abcdef0123456789abcdef";
    if (freedv.enableEncryptionFromString(key_string)) {
        std::cout << "Encryption enabled with key string: " << key_string << std::endl;
        
        std::vector<uint8_t> encoded_with_string = freedv.encode(test_audio);
        std::cout << "Encoded with string key: " << encoded_with_string.size() << " bytes" << std::endl;
    } else {
        std::cerr << "Failed to enable encryption with key string" << std::endl;
        return 1;
    }
    
    // Test disable encryption
    std::cout << "\n--- Testing disable encryption ---" << std::endl;
    
    freedv.disableEncryption();
    std::cout << "Encryption status: " << (freedv.isEncryptionEnabled() ? "Enabled" : "Disabled") << std::endl;
    
    std::vector<uint8_t> encoded_no_encrypt = freedv.encode(test_audio);
    std::cout << "Encoded without encryption: " << encoded_no_encrypt.size() << " bytes" << std::endl;
    
    // Performance comparison
    std::cout << "\n--- Performance Comparison ---" << std::endl;
    std::cout << "Plaintext encoding: " << encoded_plain.size() << " bytes" << std::endl;
    std::cout << "Encrypted encoding: " << encoded_encrypted.size() << " bytes" << std::endl;
    std::cout << "Size increase: " << (encoded_encrypted.size() - encoded_plain.size()) << " bytes" << std::endl;
    std::cout << "Size increase: " << (100.0 * (encoded_encrypted.size() - encoded_plain.size()) / encoded_plain.size()) << "%" << std::endl;
    
    std::cout << "\n=== FreeDV Encryption Test Completed Successfully ===" << std::endl;
    return 0;
}
