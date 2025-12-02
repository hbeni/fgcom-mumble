/**
 * @file encryption_system_registry.cpp
 * @brief Registration of Built-in Encryption Systems
 * 
 * This file registers all built-in encryption systems with the factory,
 * enabling modular and extensible encryption support.
 */

#include "encryption_system_interface.h"
#include "../systems/yachta-t219/include/yachta_t219.h"
#include "../systems/vinson-ky57/include/vinson_ky57.h"
#include "../systems/granit/include/granit.h"
#include "../systems/stanag-4197/include/stanag_4197.h"
#include <fstream>
#include <sstream>

namespace fgcom {
namespace voice_encryption {

/**
 * @brief Adapter wrapper for Yachta T-219 system
 */
class YachtaT219Adapter : public IEncryptionSystem {
private:
    std::unique_ptr<yachta::YachtaT219> system_;
    bool initialized_;
    
public:
    YachtaT219Adapter() : initialized_(false) {
        system_ = std::make_unique<yachta::YachtaT219>();
    }
    
    bool initialize(float sample_rate, uint32_t channels) override {
        initialized_ = system_->initialize(sample_rate, channels);
        return initialized_;
    }
    
    void shutdown() override {
        initialized_ = false;
    }
    
    EncryptionSystem getSystemType() const override {
        return EncryptionSystem::YACHTA_T219;
    }
    
    std::string getSystemName() const override {
        return "Yachta T-219";
    }
    
    std::string getSystemDescription() const override {
        return "Soviet frequency-domain voice scrambling system with FSK sync signal";
    }
    
    std::vector<float> encrypt(const std::vector<float>& input) override {
        if (!initialized_) return input;
        return system_->encrypt(input);
    }
    
    std::vector<float> decrypt(const std::vector<float>& input) override {
        if (!initialized_) return input;
        return system_->decrypt(input);
    }
    
    bool setKey(uint32_t key_id, const std::string& key_data) override {
        if (!initialized_) return false;
        return system_->setKey(key_id, key_data);
    }
    
    bool loadKeyFromFile(const std::string& filename) override {
        if (!initialized_) return false;
        std::ifstream file(filename);
        if (!file.is_open()) return false;
        std::string key_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        system_->setKeyCardData(key_data);
        return true;
    }
    
    bool saveKeyToFile(const std::string& filename) override {
        if (!initialized_) return false;
        std::ofstream file(filename);
        if (!file.is_open()) return false;
        file << system_->getKeyCardData();
        return true;
    }
    
    bool validateKey(const std::string& key_data) override {
        return yachta::YachtaUtils::validateKeyCardFormat(key_data);
    }
    
    bool isEncryptionActive() const override {
        if (!initialized_) return false;
        return system_->isActive();
    }
    
    bool isInitialized() const override {
        return initialized_;
    }
    
    std::string getKeyInfo() const override {
        if (!initialized_) return "Not initialized";
        return system_->getEncryptionStatus();
    }
    
    std::string getStatus() const override {
        return initialized_ ? "Initialized" : "Not initialized";
    }
    
    std::string getCapabilities() const override {
        return "Frequency-domain scrambling, FSK sync signal";
    }
    
    bool setParameters(const std::map<std::string, std::string>& parameters) override {
        // Implementation would parse parameters and set them
        return true;
    }
    
    std::map<std::string, std::string> getParameters() const override {
        return std::map<std::string, std::string>();
    }
};

/**
 * @brief Adapter wrapper for VINSON KY-57 system
 */
class VinsonKY57Adapter : public IEncryptionSystem {
private:
    std::unique_ptr<vinson::VinsonKY57> system_;
    bool initialized_;
    
public:
    VinsonKY57Adapter() : initialized_(false) {
        system_ = std::make_unique<vinson::VinsonKY57>();
    }
    
    bool initialize(float sample_rate, uint32_t channels) override {
        initialized_ = system_->initialize(sample_rate, channels);
        return initialized_;
    }
    
    void shutdown() override {
        initialized_ = false;
    }
    
    EncryptionSystem getSystemType() const override {
        return EncryptionSystem::VINSON_KY57;
    }
    
    std::string getSystemName() const override {
        return "VINSON KY-57";
    }
    
    std::string getSystemDescription() const override {
        return "NATO digital CVSD secure voice system with Type 1 encryption";
    }
    
    std::vector<float> encrypt(const std::vector<float>& input) override {
        if (!initialized_) return input;
        return system_->encrypt(input);
    }
    
    std::vector<float> decrypt(const std::vector<float>& input) override {
        if (!initialized_) return input;
        return system_->decrypt(input);
    }
    
    bool setKey(uint32_t key_id, const std::string& key_data) override {
        if (!initialized_) return false;
        return system_->setKey(key_id, key_data);
    }
    
    bool loadKeyFromFile(const std::string& filename) override {
        if (!initialized_) return false;
        return system_->loadKeyFromFile(filename);
    }
    
    bool saveKeyToFile(const std::string& filename) override {
        if (!initialized_) return false;
        return system_->saveKeyFromFile(filename);
    }
    
    bool validateKey(const std::string& key_data) override {
        return system_->validateKey(key_data);
    }
    
    bool isEncryptionActive() const override {
        if (!initialized_) return false;
        return system_->isEncryptionActive();
    }
    
    bool isInitialized() const override {
        return initialized_;
    }
    
    std::string getKeyInfo() const override {
        if (!initialized_) return "Not initialized";
        return system_->getKeyInfo();
    }
    
    std::string getStatus() const override {
        return initialized_ ? "Initialized" : "Not initialized";
    }
    
    std::string getCapabilities() const override {
        return "CVSD encoding, Type 1 encryption";
    }
    
    bool setParameters(const std::map<std::string, std::string>& parameters) override {
        return true;
    }
    
    std::map<std::string, std::string> getParameters() const override {
        return std::map<std::string, std::string>();
    }
};

/**
 * @brief Adapter wrapper for Granit system
 */
class GranitAdapter : public IEncryptionSystem {
private:
    std::unique_ptr<granit::Granit> system_;
    bool initialized_;
    
public:
    GranitAdapter() : initialized_(false) {
        system_ = std::make_unique<granit::Granit>();
    }
    
    bool initialize(float sample_rate, uint32_t channels) override {
        initialized_ = system_->initialize(sample_rate, channels);
        return initialized_;
    }
    
    void shutdown() override {
        initialized_ = false;
    }
    
    EncryptionSystem getSystemType() const override {
        return EncryptionSystem::GRANIT;
    }
    
    std::string getSystemName() const override {
        return "Granit";
    }
    
    std::string getSystemDescription() const override {
        return "Soviet time-domain scrambling system with temporal distortion effects";
    }
    
    std::vector<float> encrypt(const std::vector<float>& input) override {
        if (!initialized_) return input;
        return system_->encrypt(input);
    }
    
    std::vector<float> decrypt(const std::vector<float>& input) override {
        if (!initialized_) return input;
        return system_->decrypt(input);
    }
    
    bool setKey(uint32_t key_id, const std::string& key_data) override {
        if (!initialized_) return false;
        return system_->setKey(key_id, key_data);
    }
    
    bool loadKeyFromFile(const std::string& filename) override {
        if (!initialized_) return false;
        return system_->loadKeyFromFile(filename);
    }
    
    bool saveKeyToFile(const std::string& filename) override {
        if (!initialized_) return false;
        return system_->saveKeyToFile(filename);
    }
    
    bool validateKey(const std::string& key_data) override {
        return system_->validateKey(key_data);
    }
    
    bool isEncryptionActive() const override {
        if (!initialized_) return false;
        return system_->isScramblingActive();
    }
    
    bool isInitialized() const override {
        return initialized_;
    }
    
    std::string getKeyInfo() const override {
        if (!initialized_) return "Not initialized";
        return system_->getKeyInfo();
    }
    
    std::string getStatus() const override {
        return initialized_ ? "Initialized" : "Not initialized";
    }
    
    std::string getCapabilities() const override {
        return "Time-domain scrambling, temporal distortion";
    }
    
    bool setParameters(const std::map<std::string, std::string>& parameters) override {
        return true;
    }
    
    std::map<std::string, std::string> getParameters() const override {
        return std::map<std::string, std::string>();
    }
};

/**
 * @brief Adapter wrapper for STANAG 4197 system
 */
class Stanag4197Adapter : public IEncryptionSystem {
private:
    std::unique_ptr<stanag4197::Stanag4197> system_;
    bool initialized_;
    
public:
    Stanag4197Adapter() : initialized_(false) {
        system_ = std::make_unique<stanag4197::Stanag4197>();
    }
    
    bool initialize(float sample_rate, uint32_t channels) override {
        initialized_ = system_->initialize(sample_rate, channels);
        return initialized_;
    }
    
    void shutdown() override {
        initialized_ = false;
    }
    
    EncryptionSystem getSystemType() const override {
        return EncryptionSystem::STANAG_4197;
    }
    
    std::string getSystemName() const override {
        return "STANAG 4197";
    }
    
    std::string getSystemDescription() const override {
        return "NATO QPSK OFDM digital voice system for HF communications";
    }
    
    std::vector<float> encrypt(const std::vector<float>& input) override {
        if (!initialized_) return input;
        return system_->encrypt(input);
    }
    
    std::vector<float> decrypt(const std::vector<float>& input) override {
        if (!initialized_) return input;
        return system_->decrypt(input);
    }
    
    bool setKey(uint32_t key_id, const std::string& key_data) override {
        if (!initialized_) return false;
        return system_->setKey(key_id, key_data);
    }
    
    bool loadKeyFromFile(const std::string& filename) override {
        if (!initialized_) return false;
        return system_->loadKeyFromFile(filename);
    }
    
    bool saveKeyToFile(const std::string& filename) override {
        if (!initialized_) return false;
        return system_->saveKeyToFile(filename);
    }
    
    bool validateKey(const std::string& key_data) override {
        return system_->validateKey(key_data);
    }
    
    bool isEncryptionActive() const override {
        if (!initialized_) return false;
        return system_->isEncryptionActive();
    }
    
    bool isInitialized() const override {
        return initialized_;
    }
    
    std::string getKeyInfo() const override {
        if (!initialized_) return "Not initialized";
        return system_->getKeyInfo();
    }
    
    std::string getStatus() const override {
        return initialized_ ? "Initialized" : "Not initialized";
    }
    
    std::string getCapabilities() const override {
        return "QPSK OFDM modulation, HF communications";
    }
    
    bool setParameters(const std::map<std::string, std::string>& parameters) override {
        return true;
    }
    
    std::map<std::string, std::string> getParameters() const override {
        return std::map<std::string, std::string>();
    }
};

/**
 * @brief Register all built-in encryption systems
 * 
 * This function should be called during module initialization
 * to register all built-in encryption systems with the factory.
 */
void registerBuiltInEncryptionSystems() {
    auto& factory = EncryptionSystemFactory::getInstance();
    
    factory.registerSystem(EncryptionSystem::YACHTA_T219, []() {
        return std::unique_ptr<IEncryptionSystem>(new YachtaT219Adapter());
    });
    
    factory.registerSystem(EncryptionSystem::VINSON_KY57, []() {
        return std::unique_ptr<IEncryptionSystem>(new VinsonKY57Adapter());
    });
    
    factory.registerSystem(EncryptionSystem::GRANIT, []() {
        return std::unique_ptr<IEncryptionSystem>(new GranitAdapter());
    });
    
    factory.registerSystem(EncryptionSystem::STANAG_4197, []() {
        return std::unique_ptr<IEncryptionSystem>(new Stanag4197Adapter());
    });
}

} // namespace voice_encryption
} // namespace fgcom

