/**
 * @file voice_encryption.cpp
 * @brief Voice Encryption Module Implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of the voice encryption module,
 * providing unified access to all Cold War era encryption systems.
 * 
 * @details
 * The implementation provides:
 * - Unified API for all encryption systems
 * - System management and switching
 * - Key management and validation
 * - Audio processing and effects
 * - Status reporting and diagnostics
 * 
 * @see voice_encryption.h
 * @see docs/VOICE_ENCRYPTION_MODULE.md
 */

#include "voice_encryption.h"
#include "encryption_system_registry.h"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <sstream>
#include <fstream>

namespace fgcom {
namespace voice_encryption {

/**
 * @brief VoiceEncryptionManager Implementation
 * 
 * @details
 * This section contains the complete implementation of the
 * VoiceEncryptionManager class.
 */

/**
 * @brief Constructor for VoiceEncryptionManager
 * 
 * @details
 * Initializes the voice encryption manager with default parameters.
 * All encryption systems are created but not initialized.
 */
VoiceEncryptionManager::VoiceEncryptionManager()
    : current_system_(EncryptionSystem::YACHTA_T219)
    , initialized_(false)
    , current_system_instance_(nullptr)
    , factory_(&EncryptionSystemFactory::getInstance())
    , sample_rate_(44100.0f)
    , channels_(1) {
    
    // Register all built-in encryption systems
    registerBuiltInEncryptionSystems();
}

/**
 * @brief Destructor for VoiceEncryptionManager
 * 
 * @details
 * Cleans up all resources used by the voice encryption manager.
 */
VoiceEncryptionManager::~VoiceEncryptionManager() {
    // Cleanup resources
}

/**
 * @brief Initialize the voice encryption manager
 * 
 * @param sample_rate Audio sample rate in Hz
 * @param channels Number of audio channels
 * @return true if initialization successful, false otherwise
 * 
 * @details
 * Initializes the voice encryption manager with the specified
 * audio parameters. All encryption systems are initialized.
 */
bool VoiceEncryptionManager::initialize(float sample_rate, uint32_t channels) {
    if (sample_rate <= 0.0f || channels == 0) {
        return false;
    }
    
    sample_rate_ = sample_rate;
    channels_ = channels;
    
    // Create and initialize current system
    current_system_instance_ = factory_->createSystem(current_system_);
    if (!current_system_instance_) {
        return false;
    }
    
    if (!current_system_instance_->initialize(sample_rate, channels)) {
        return false;
    }
    
    initialized_ = true;
    return true;
}

/**
 * @brief Set encryption system
 * 
 * @param system Encryption system to use
 * @return true if system set successfully, false otherwise
 * 
 * @details
 * Sets the active encryption system for voice encryption.
 */
bool VoiceEncryptionManager::setEncryptionSystem(EncryptionSystem system) {
    if (!factory_->isSystemRegistered(system)) {
        return false;
    }
    
    // Create new system instance
    auto new_system = factory_->createSystem(system);
    if (!new_system) {
        return false;
    }
    
    // Initialize if manager is already initialized
    if (initialized_) {
        if (!new_system->initialize(sample_rate_, channels_)) {
            return false;
        }
    }
    
    // Shutdown old system
    if (current_system_instance_) {
        current_system_instance_->shutdown();
    }
    
    // Switch to new system
    current_system_instance_ = std::move(new_system);
    current_system_ = system;
    
    return true;
}

/**
 * @brief Get current encryption system
 * 
 * @return Current encryption system
 * 
 * @details
 * Returns the currently active encryption system.
 */
EncryptionSystem VoiceEncryptionManager::getCurrentSystem() const {
    return current_system_;
}

/**
 * @brief Encrypt audio data
 * 
 * @param input Input audio samples
 * @return Encrypted audio samples
 * 
 * @details
 * Encrypts the input audio using the currently active
 * encryption system.
 */
std::vector<float> VoiceEncryptionManager::encrypt(const std::vector<float>& input) {
    if (!initialized_ || input.empty() || !current_system_instance_) {
        return input;
    }
    
    return current_system_instance_->encrypt(input);
}

/**
 * @brief Decrypt audio data
 * 
 * @param input Encrypted audio samples
 * @return Decrypted audio samples
 * 
 * @details
 * Decrypts the input audio using the currently active
 * encryption system.
 */
std::vector<float> VoiceEncryptionManager::decrypt(const std::vector<float>& input) {
    if (!initialized_ || input.empty() || !current_system_instance_) {
        return input;
    }
    
    return current_system_instance_->decrypt(input);
}

/**
 * @brief Set encryption key
 * 
 * @param key_id Key identifier
 * @param key_data Key data string
 * @return true if key set successfully, false otherwise
 * 
 * @details
 * Sets the encryption key for the currently active system.
 */
bool VoiceEncryptionManager::setKey(uint32_t key_id, const std::string& key_data) {
    if (!initialized_ || !current_system_instance_) {
        return false;
    }
    
    return current_system_instance_->setKey(key_id, key_data);
}

/**
 * @brief Load key from file
 * 
 * @param filename Key file path
 * @return true if key loaded successfully, false otherwise
 * 
 * @details
 * Loads encryption key from a file for the currently active system.
 */
bool VoiceEncryptionManager::loadKeyFromFile(const std::string& filename) {
    if (!initialized_ || !current_system_instance_) {
        return false;
    }
    
    return current_system_instance_->loadKeyFromFile(filename);
}

/**
 * @brief Save key to file
 * 
 * @param filename Key file path
 * @return true if key saved successfully, false otherwise
 * 
 * @details
 * Saves encryption key to a file for the currently active system.
 */
bool VoiceEncryptionManager::saveKeyToFile(const std::string& filename) {
    if (!initialized_ || !current_system_instance_) {
        return false;
    }
    
    return current_system_instance_->saveKeyToFile(filename);
}

/**
 * @brief Validate key
 * 
 * @param key_data Key data string to validate
 * @return true if key is valid, false otherwise
 * 
 * @details
 * Validates that the key data meets requirements for the
 * currently active system.
 */
bool VoiceEncryptionManager::validateKey(const std::string& key_data) {
    if (!initialized_ || !current_system_instance_) {
        return false;
    }
    
    return current_system_instance_->validateKey(key_data);
}

/**
 * @brief Set Yachta T-219 parameters
 * 
 * @param segment_size Segment size in samples
 * @param scrambling_depth Scrambling depth
 * @param intensity Scrambling intensity
 * @return true if parameters set successfully, false otherwise
 * 
 * @details
 * Sets parameters for the Yachta T-219 system.
 */
bool VoiceEncryptionManager::setYachtaT219Parameters(uint32_t segment_size, uint32_t scrambling_depth, float intensity) {
    if (!initialized_) {
        return false;
    }
    
    // Yachta system expects vector of segments, not individual parameters
    std::vector<uint32_t> segments = {segment_size};
    yachta_t219_->setScramblingParameters(segments, intensity);
    return true;
}

/**
 * @brief Set VINSON KY-57 parameters
 * 
 * @param cvsd_rate CVSD rate in bps
 * @param quality Digital voice quality
 * @return true if parameters set successfully, false otherwise
 * 
 * @details
 * Sets parameters for the VINSON KY-57 system.
 */
bool VoiceEncryptionManager::setVinsonKY57Parameters(float cvsd_rate, float quality) {
    if (!initialized_) {
        return false;
    }
    
    // VINSON system expects 3 parameters: bit_rate, step_size, adaptation_rate
    vinson_ky57_->setCVSDParameters(static_cast<uint32_t>(cvsd_rate), quality, quality * 0.1f);
    return true;
}

/**
 * @brief Set Granit parameters
 * 
 * @param segment_size Segment size in samples
 * @param scrambling_depth Scrambling depth
 * @param pilot_freq Pilot signal frequency
 * @return true if parameters set successfully, false otherwise
 * 
 * @details
 * Sets parameters for the Granit system.
 */
bool VoiceEncryptionManager::setGranitParameters(uint32_t segment_size, uint32_t scrambling_depth, float pilot_freq) {
    if (!initialized_) {
        return false;
    }
    
    return granit_->setScramblingParameters(segment_size, scrambling_depth, pilot_freq);
}

/**
 * @brief Set STANAG 4197 parameters
 * 
 * @param data_rate Data rate in bps
 * @param ofdm_tones Number of OFDM tones
 * @param header_tones Number of header tones
 * @return true if parameters set successfully, false otherwise
 * 
 * @details
 * Sets parameters for the STANAG 4197 system.
 */
bool VoiceEncryptionManager::setStanag4197Parameters(uint32_t data_rate, uint32_t ofdm_tones, uint32_t header_tones) {
    if (!initialized_) {
        return false;
    }
    
    return stanag_4197_->setOFDMParameters(data_rate, ofdm_tones, header_tones);
}

/**
 * @brief Check if system is initialized
 * 
 * @return true if initialized, false otherwise
 * 
 * @details
 * Returns the initialization status of the voice encryption manager.
 */
bool VoiceEncryptionManager::isInitialized() const {
    return initialized_;
}

/**
 * @brief Check if encryption is active
 * 
 * @return true if encryption is active, false otherwise
 * 
 * @details
 * Returns the encryption status of the currently active system.
 */
bool VoiceEncryptionManager::isEncryptionActive() const {
    if (!initialized_ || !current_system_instance_) {
        return false;
    }
    
    return current_system_instance_->isEncryptionActive();
}

/**
 * @brief Get system status
 * 
 * @return Status string
 * 
 * @details
 * Returns a string describing the current status of the
 * voice encryption manager.
 */
std::string VoiceEncryptionManager::getStatus() const {
    std::ostringstream oss;
    oss << "Voice Encryption Manager Status: ";
    oss << "Initialized=" << (initialized_ ? "Yes" : "No") << ", ";
    oss << "Current System=" << VoiceEncryptionUtils::getSystemName(current_system_) << ", ";
    oss << "Encryption=" << (isEncryptionActive() ? "Active" : "Inactive");
    return oss.str();
}

/**
 * @brief Get key information
 * 
 * @return Key information string
 * 
 * @details
 * Returns a string describing the current key information
 * of the currently active system.
 */
std::string VoiceEncryptionManager::getKeyInfo() const {
    if (!initialized_ || !current_system_instance_) {
        return "System not initialized";
    }
    
    return current_system_instance_->getKeyInfo();
}

/**
 * @brief Get available systems
 * 
 * @return Vector of available encryption systems
 * 
 * @details
 * Returns a list of all available encryption systems.
 */
std::vector<EncryptionSystem> VoiceEncryptionManager::getAvailableSystems() const {
    return factory_->getRegisteredSystems();
}

/**
 * @brief Get system information
 * 
 * @param system Encryption system
 * @return System information string
 * 
 * @details
 * Returns detailed information about the specified encryption system.
 */
std::string VoiceEncryptionManager::getSystemInfo(EncryptionSystem system) const {
    std::ostringstream oss;
    oss << "System: " << VoiceEncryptionUtils::getSystemName(system) << "\n";
    oss << "Description: " << VoiceEncryptionUtils::getSystemDescription(system) << "\n";
    oss << "Characteristics: " << VoiceEncryptionUtils::getSystemCharacteristics(system);
    return oss.str();
}

// VoiceEncryptionUtils namespace implementation

namespace VoiceEncryptionUtils {

EncryptionSystem detectEncryptionSystem(const std::vector<float>& audio) {
    if (audio.empty()) {
        return EncryptionSystem::YACHTA_T219; // Default
    }
    
    // Simple detection algorithm based on audio characteristics
    // In real implementation, this would be more sophisticated
    
    // Calculate RMS
    float rms = 0.0f;
    for (float sample : audio) {
        rms += sample * sample;
    }
    rms = std::sqrt(rms / audio.size());
    
    // Simple heuristics for system detection
    if (rms < 0.1f) {
        return EncryptionSystem::YACHTA_T219; // Low amplitude - Yachta
    } else if (rms < 0.3f) {
        return EncryptionSystem::VINSON_KY57; // Medium amplitude - VINSON
    } else if (rms < 0.5f) {
        return EncryptionSystem::GRANIT; // Higher amplitude - Granit
    } else {
        return EncryptionSystem::STANAG_4197; // High amplitude - STANAG 4197
    }
}

std::string getSystemName(EncryptionSystem system) {
    switch (system) {
        case EncryptionSystem::YACHTA_T219:
            return "Yachta T-219";
        case EncryptionSystem::VINSON_KY57:
            return "VINSON KY-57";
        case EncryptionSystem::GRANIT:
            return "Granit";
        case EncryptionSystem::STANAG_4197:
            return "STANAG 4197";
        default:
            return "Unknown";
    }
}

std::string getSystemDescription(EncryptionSystem system) {
    switch (system) {
        case EncryptionSystem::YACHTA_T219:
            return "Soviet frequency-domain voice scrambling system with FSK sync signal";
        case EncryptionSystem::VINSON_KY57:
            return "NATO digital CVSD secure voice system with Type 1 encryption";
        case EncryptionSystem::GRANIT:
            return "Soviet time-domain scrambling system with temporal distortion effects";
        case EncryptionSystem::STANAG_4197:
            return "NATO QPSK OFDM digital voice system for HF communications";
        default:
            return "Unknown encryption system";
    }
}

std::string getSystemCharacteristics(EncryptionSystem system) {
    switch (system) {
        case EncryptionSystem::YACHTA_T219:
            return "Warbled, Donald Duck sound with FSK sync signal";
        case EncryptionSystem::VINSON_KY57:
            return "Robotic, buzzy digital voice with CVSD encoding";
        case EncryptionSystem::GRANIT:
            return "Segmented, time-jumped sound with temporal distortion";
        case EncryptionSystem::STANAG_4197:
            return "Digital voice with QPSK OFDM modulation";
        default:
            return "Unknown audio characteristics";
    }
}

void applyAudioEffects(std::vector<float>& audio, EncryptionSystem system, float intensity) {
    if (audio.empty() || intensity <= 0.0f) {
        return;
    }
    
    switch (system) {
        case EncryptionSystem::YACHTA_T219:
            // Apply Yachta effects
            for (size_t i = 0; i < audio.size(); ++i) {
                float sample = audio[i];
                float modulation = std::sin(2.0f * M_PI * 100.0f * i / 44100.0f) * intensity;
                sample = sample * (1.0f + modulation);
                audio[i] = sample;
            }
            break;
        case EncryptionSystem::VINSON_KY57:
            // Apply VINSON effects
            for (size_t i = 0; i < audio.size(); ++i) {
                float sample = audio[i];
                sample = std::round(sample * 16.0f) / 16.0f; // Quantization
                audio[i] = sample;
            }
            break;
        case EncryptionSystem::GRANIT:
            // Apply Granit effects
            for (size_t i = 0; i < audio.size(); ++i) {
                float sample = audio[i];
                if (i % 100 == 0) {
                    sample *= (1.0f + intensity * 0.5f); // Time-jump effect
                }
                audio[i] = sample;
            }
            break;
        case EncryptionSystem::STANAG_4197:
            // Apply STANAG 4197 effects
            for (size_t i = 0; i < audio.size(); ++i) {
                float sample = audio[i];
                float modulation = std::sin(2.0f * M_PI * 100.0f * i / 44100.0f) * intensity;
                sample = sample * (1.0f + modulation);
                audio[i] = sample;
            }
            break;
        default:
            break;
    }
}

std::vector<float> generateTestAudio(EncryptionSystem system, float sample_rate, float duration) {
    std::vector<float> audio;
    int samples = static_cast<int>(sample_rate * duration);
    
    // Generate base tone
    for (int i = 0; i < samples; ++i) {
        float sample = std::sin(2.0f * M_PI * 1000.0f * i / sample_rate);
        audio.push_back(sample);
    }
    
    // Apply system-specific effects
    applyAudioEffects(audio, system, 0.8f);
    
    return audio;
}

bool validateAudioParameters(float sample_rate, uint32_t channels) {
    return sample_rate > 0.0f && channels > 0 && channels <= 2;
}

std::vector<float> getSupportedSampleRates() {
    return {8000.0f, 16000.0f, 22050.0f, 44100.0f, 48000.0f};
}

std::vector<uint32_t> getSupportedChannelCounts() {
    return {1, 2}; // Mono and stereo
}

} // namespace VoiceEncryptionUtils

} // namespace voice_encryption
} // namespace fgcom