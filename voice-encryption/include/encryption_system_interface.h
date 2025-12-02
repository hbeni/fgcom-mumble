/**
 * @file encryption_system_interface.h
 * @brief Abstract Interface for Voice Encryption Systems
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file defines the abstract interface that all voice encryption
 * systems must implement, enabling modular and extensible encryption support.
 */

#ifndef ENCRYPTION_SYSTEM_INTERFACE_H
#define ENCRYPTION_SYSTEM_INTERFACE_H

#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <map>
#include <mutex>
#include <functional>

namespace fgcom {
namespace voice_encryption {

/**
 * @enum EncryptionSystem
 * @brief Available voice encryption systems
 */
enum class EncryptionSystem {
    YACHTA_T219,    ///< Soviet Yachta T-219 frequency-domain scrambling
    VINSON_KY57,    ///< NATO VINSON KY-57 digital CVSD secure voice
    GRANIT,         ///< Soviet Granit time-domain scrambling
    STANAG_4197,   ///< NATO STANAG 4197 QPSK OFDM digital voice
    FREEDV,         ///< Modern FreeDV digital voice with multiple modes
    MELPE           ///< NATO MELPe vocoder (STANAG 4591)
};

/**
 * @class IEncryptionSystem
 * @brief Abstract interface for voice encryption systems
 * 
 * @details
 * This interface defines the contract that all voice encryption systems
 * must implement. This enables modular design where new encryption systems
 * can be added without modifying existing code.
 * 
 * All encryption systems must implement:
 * - Initialization and cleanup
 * - Encryption and decryption operations
 * - Key management
 * - Status reporting
 */
class IEncryptionSystem {
public:
    virtual ~IEncryptionSystem() = default;
    
    /**
     * @brief Initialize the encryption system
     * 
     * @param sample_rate Audio sample rate in Hz
     * @param channels Number of audio channels
     * @return true if initialization successful, false otherwise
     */
    virtual bool initialize(float sample_rate, uint32_t channels) = 0;
    
    /**
     * @brief Shutdown the encryption system
     * 
     * @details
     * Cleans up all resources used by the encryption system.
     */
    virtual void shutdown() = 0;
    
    /**
     * @brief Get the encryption system type
     * 
     * @return Encryption system type
     */
    virtual EncryptionSystem getSystemType() const = 0;
    
    /**
     * @brief Get the system name
     * 
     * @return Human-readable system name
     */
    virtual std::string getSystemName() const = 0;
    
    /**
     * @brief Get the system description
     * 
     * @return Detailed system description
     */
    virtual std::string getSystemDescription() const = 0;
    
    /**
     * @brief Encrypt audio data
     * 
     * @param input Input audio samples
     * @return Encrypted audio samples
     */
    virtual std::vector<float> encrypt(const std::vector<float>& input) = 0;
    
    /**
     * @brief Decrypt audio data
     * 
     * @param input Encrypted audio samples
     * @return Decrypted audio samples
     */
    virtual std::vector<float> decrypt(const std::vector<float>& input) = 0;
    
    /**
     * @brief Set encryption key
     * 
     * @param key_id Key identifier
     * @param key_data Key data string
     * @return true if key set successfully, false otherwise
     */
    virtual bool setKey(uint32_t key_id, const std::string& key_data) = 0;
    
    /**
     * @brief Load key from file
     * 
     * @param filename Key file path
     * @return true if key loaded successfully, false otherwise
     */
    virtual bool loadKeyFromFile(const std::string& filename) = 0;
    
    /**
     * @brief Save key to file
     * 
     * @param filename Key file path
     * @return true if key saved successfully, false otherwise
     */
    virtual bool saveKeyToFile(const std::string& filename) = 0;
    
    /**
     * @brief Validate key
     * 
     * @param key_data Key data string to validate
     * @return true if key is valid, false otherwise
     */
    virtual bool validateKey(const std::string& key_data) = 0;
    
    /**
     * @brief Check if encryption is active
     * 
     * @return true if encryption is active, false otherwise
     */
    virtual bool isEncryptionActive() const = 0;
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     */
    virtual bool isInitialized() const = 0;
    
    /**
     * @brief Get key information
     * 
     * @return Key information string
     */
    virtual std::string getKeyInfo() const = 0;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     */
    virtual std::string getStatus() const = 0;
    
    /**
     * @brief Get system capabilities
     * 
     * @return Capabilities string
     */
    virtual std::string getCapabilities() const = 0;
    
    /**
     * @brief Set system-specific parameters
     * 
     * @param parameters Parameter map (key-value pairs)
     * @return true if parameters set successfully, false otherwise
     */
    virtual bool setParameters(const std::map<std::string, std::string>& parameters) = 0;
    
    /**
     * @brief Get system-specific parameters
     * 
     * @return Parameter map (key-value pairs)
     */
    virtual std::map<std::string, std::string> getParameters() const = 0;
};

/**
 * @class EncryptionSystemFactory
 * @brief Factory for creating encryption system instances
 * 
 * @details
 * This factory class provides a way to create instances of encryption
 * systems dynamically. It uses a registry pattern to allow registration
 * of custom encryption systems.
 */
class EncryptionSystemFactory {
public:
    /**
     * @brief Factory function type for creating encryption systems
     */
    using FactoryFunction = std::function<std::unique_ptr<IEncryptionSystem>()>;
    
    /**
     * @brief Get singleton instance
     * 
     * @return Reference to factory instance
     */
    static EncryptionSystemFactory& getInstance();
    
    /**
     * @brief Register an encryption system factory function
     * 
     * @param system_type Encryption system type
     * @param factory_function Factory function that creates the system
     * @return true if registration successful, false otherwise
     */
    bool registerSystem(EncryptionSystem system_type, FactoryFunction factory_function);
    
    /**
     * @brief Unregister an encryption system
     * 
     * @param system_type Encryption system type
     * @return true if unregistration successful, false otherwise
     */
    bool unregisterSystem(EncryptionSystem system_type);
    
    /**
     * @brief Create an encryption system instance
     * 
     * @param system_type Encryption system type
     * @return Unique pointer to encryption system instance, or nullptr if not found
     */
    std::unique_ptr<IEncryptionSystem> createSystem(EncryptionSystem system_type);
    
    /**
     * @brief Check if a system is registered
     * 
     * @param system_type Encryption system type
     * @return true if registered, false otherwise
     */
    bool isSystemRegistered(EncryptionSystem system_type) const;
    
    /**
     * @brief Get all registered system types
     * 
     * @return Vector of registered encryption system types
     */
    std::vector<EncryptionSystem> getRegisteredSystems() const;
    
    /**
     * @brief Clear all registered systems
     */
    void clearRegistry();
    
private:
    EncryptionSystemFactory() = default;
    ~EncryptionSystemFactory() = default;
    EncryptionSystemFactory(const EncryptionSystemFactory&) = delete;
    EncryptionSystemFactory& operator=(const EncryptionSystemFactory&) = delete;
    
    std::map<EncryptionSystem, FactoryFunction> registry_;
    mutable std::mutex registry_mutex_;
    
    static std::unique_ptr<EncryptionSystemFactory> instance_;
    static std::mutex instance_mutex_;
};

} // namespace voice_encryption
} // namespace fgcom

#endif // ENCRYPTION_SYSTEM_INTERFACE_H

