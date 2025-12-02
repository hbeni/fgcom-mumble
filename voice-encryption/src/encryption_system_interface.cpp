/**
 * @file encryption_system_interface.cpp
 * @brief Implementation of Encryption System Interface and Factory
 */

#include "encryption_system_interface.h"
#include <mutex>
#include <algorithm>
#include <map>

namespace fgcom {
namespace voice_encryption {

// Static member definitions
std::unique_ptr<EncryptionSystemFactory> EncryptionSystemFactory::instance_ = nullptr;
std::mutex EncryptionSystemFactory::instance_mutex_;

EncryptionSystemFactory& EncryptionSystemFactory::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = std::unique_ptr<EncryptionSystemFactory>(new EncryptionSystemFactory());
    }
    return *instance_;
}

bool EncryptionSystemFactory::registerSystem(EncryptionSystem system_type, FactoryFunction factory_function) {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    
    if (!factory_function) {
        return false;
    }
    
    registry_[system_type] = factory_function;
    return true;
}

bool EncryptionSystemFactory::unregisterSystem(EncryptionSystem system_type) {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    
    auto it = registry_.find(system_type);
    if (it == registry_.end()) {
        return false;
    }
    
    registry_.erase(it);
    return true;
}

std::unique_ptr<IEncryptionSystem> EncryptionSystemFactory::createSystem(EncryptionSystem system_type) {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    
    auto it = registry_.find(system_type);
    if (it == registry_.end()) {
        return nullptr;
    }
    
    return it->second();
}

bool EncryptionSystemFactory::isSystemRegistered(EncryptionSystem system_type) const {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    return registry_.find(system_type) != registry_.end();
}

std::vector<EncryptionSystem> EncryptionSystemFactory::getRegisteredSystems() const {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    
    std::vector<EncryptionSystem> systems;
    for (const auto& pair : registry_) {
        systems.push_back(pair.first);
    }
    return systems;
}

void EncryptionSystemFactory::clearRegistry() {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    registry_.clear();
}

} // namespace voice_encryption
} // namespace fgcom

