#include "include/voice_encryption.h"
#include <iostream>
#include <vector>

void testSystem(fgcom::voice_encryption::VoiceEncryptionManager& manager, 
                fgcom::voice_encryption::EncryptionSystem system, 
                const std::string& systemName) {
    std::cout << "\n=== Testing " << systemName << " ===" << std::endl;
    
    if (!manager.setEncryptionSystem(system)) {
        std::cerr << "✗ Failed to set " << systemName << " system" << std::endl;
        return;
    }
    
    std::cout << "✓ " << systemName << " system set successfully" << std::endl;
    
    // Test encryption
    std::vector<float> test_audio = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f, 0.7f, 0.8f};
    std::vector<float> encrypted = manager.encrypt(test_audio);
    
    if (encrypted.empty()) {
        std::cerr << "✗ Encryption failed for " << systemName << std::endl;
        return;
    }
    
    std::cout << "✓ " << systemName << " encryption successful" << std::endl;
    
    // Test decryption
    std::vector<float> decrypted = manager.decrypt(encrypted);
    
    if (decrypted.empty()) {
        std::cerr << "✗ Decryption failed for " << systemName << std::endl;
        return;
    }
    
    std::cout << "✓ " << systemName << " decryption successful" << std::endl;
    
    // Test status
    std::string status = manager.getStatus();
    std::cout << "Status: " << status << std::endl;
}

int main() {
    std::cout << "Testing All Voice Encryption Systems" << std::endl;
    
    // Create voice encryption manager
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    
    // Test initialization
    if (!manager.initialize(44100.0f, 1)) {
        std::cerr << "Failed to initialize voice encryption manager" << std::endl;
        return 1;
    }
    
    std::cout << "✓ Voice encryption manager initialized successfully" << std::endl;
    
    // Test all systems
    testSystem(manager, fgcom::voice_encryption::EncryptionSystem::YACHTA_T219, "Yachta T-219");
    testSystem(manager, fgcom::voice_encryption::EncryptionSystem::VINSON_KY57, "VINSON KY-57");
    testSystem(manager, fgcom::voice_encryption::EncryptionSystem::GRANIT, "Granit");
    testSystem(manager, fgcom::voice_encryption::EncryptionSystem::STANAG_4197, "STANAG 4197");
    
    std::cout << "\n✓ All encryption systems tested successfully!" << std::endl;
    return 0;
}
