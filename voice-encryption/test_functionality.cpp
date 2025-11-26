#include "include/voice_encryption.h"
#include <iostream>
#include <vector>

int main() {
    std::cout << "Testing Voice Encryption System Functionality" << std::endl;
    
    // Create voice encryption manager
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    
    // Test initialization
    if (!manager.initialize(44100.0f, 1)) {
        std::cerr << "Failed to initialize voice encryption manager" << std::endl;
        return 1;
    }
    
    std::cout << "✓ Voice encryption manager initialized successfully" << std::endl;
    
    // Test system switching
    if (!manager.setEncryptionSystem(fgcom::voice_encryption::EncryptionSystem::YACHTA_T219)) {
        std::cerr << "Failed to set Yachta T-219 system" << std::endl;
        return 1;
    }
    
    std::cout << "✓ Yachta T-219 system set successfully" << std::endl;
    
    // Test encryption with sample audio
    std::vector<float> test_audio = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};
    std::vector<float> encrypted = manager.encrypt(test_audio);
    
    if (encrypted.empty()) {
        std::cerr << "Encryption failed" << std::endl;
        return 1;
    }
    
    std::cout << "✓ Audio encryption successful" << std::endl;
    
    // Test decryption
    std::vector<float> decrypted = manager.decrypt(encrypted);
    
    if (decrypted.empty()) {
        std::cerr << "Decryption failed" << std::endl;
        return 1;
    }
    
    std::cout << "✓ Audio decryption successful" << std::endl;
    
    // Test status
    std::string status = manager.getStatus();
    std::cout << "System status: " << status << std::endl;
    
    std::cout << "✓ All functionality tests passed!" << std::endl;
    return 0;
}
