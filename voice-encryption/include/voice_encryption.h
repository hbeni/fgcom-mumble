/**
 * @file voice_encryption.h
 * @brief Voice Encryption Module API
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the main API for the voice encryption module,
 * providing access to all Cold War era encryption systems.
 * 
 * @details
 * The voice encryption module provides a unified API for accessing
 * various voice encryption systems including:
 * - Yachta T-219: Soviet frequency-domain scrambling
 * - VINSON KY-57: NATO digital CVSD secure voice
 * - Granit: Soviet time-domain scrambling
 * - STANAG 4197: NATO QPSK OFDM digital voice
 * - FreeDV: Modern digital voice with multiple bitrate modes
 * - MELPe: NATO standard vocoder (STANAG 4591)
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/VOICE_ENCRYPTION_MODULE.md
 */

#ifndef VOICE_ENCRYPTION_H
#define VOICE_ENCRYPTION_H

#include <vector>
#include <memory>
#include <string>
#include <cstdint>

// Include modular encryption system interface
#include "encryption_system_interface.h"

namespace fgcom {
namespace voice_encryption {

/**
 * @enum EncryptionSystem
 * @brief Available voice encryption systems
 * 
 * @details
 * This enumeration defines all available voice encryption systems
 * in the module.
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
 * @class VoiceEncryptionManager
 * @brief Main voice encryption manager class
 * 
 * @details
 * The VoiceEncryptionManager provides a unified interface for
 * managing all voice encryption systems in the module.
 * 
 * ## Usage Example
 * @code
 * #include "voice_encryption.h"
 * 
 * // Create voice encryption manager
 * VoiceEncryptionManager manager;
 * 
 * // Initialize with audio parameters
 * manager.initialize(44100.0f, 1);
 * 
 * // Set encryption system
 * manager.setEncryptionSystem(EncryptionSystem::YACHTA_T219);
 * 
 * // Set encryption key
 * manager.setKey(12345, "encryption_key_data");
 * 
 * // Encrypt audio
 * std::vector<float> input_audio = loadAudioData();
 * std::vector<float> encrypted_audio = manager.encrypt(input_audio);
 * @endcode
 * 
 * @note This class provides a unified interface for all encryption systems.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class VoiceEncryptionManager {
private:
    EncryptionSystem current_system_;           ///< Current encryption system
    bool initialized_;                         ///< System initialization status
    
    // Modular encryption system (uses interface)
    std::unique_ptr<IEncryptionSystem> current_system_instance_;
    
    // Encryption system factory (for creating systems)
    EncryptionSystemFactory* factory_;
    
    // Audio parameters
    float sample_rate_;                       ///< Audio sample rate
    uint32_t channels_;                       ///< Number of audio channels
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the voice encryption manager with default parameters.
     */
    VoiceEncryptionManager();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the voice encryption manager.
     */
    virtual ~VoiceEncryptionManager();
    
    // Initialization and configuration
    
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
     * 
     * @note The system must be initialized before any other operations.
     */
    bool initialize(float sample_rate, uint32_t channels);
    
    /**
     * @brief Set encryption system
     * 
     * @param system Encryption system to use
     * @return true if system set successfully, false otherwise
     * 
     * @details
     * Sets the active encryption system for voice encryption.
     * 
     * @note The system must be initialized before setting encryption system.
     */
    bool setEncryptionSystem(EncryptionSystem system);
    
    /**
     * @brief Get current encryption system
     * 
     * @return Current encryption system
     * 
     * @details
     * Returns the currently active encryption system.
     */
    EncryptionSystem getCurrentSystem() const;
    
    // Audio processing
    
    /**
     * @brief Encrypt audio data
     * 
     * @param input Input audio samples
     * @return Encrypted audio samples
     * 
     * @details
     * Encrypts the input audio using the currently active
     * encryption system.
     * 
     * @note The system must be initialized and have an encryption system set.
     */
    std::vector<float> encrypt(const std::vector<float>& input);
    
    /**
     * @brief Decrypt audio data
     * 
     * @param input Encrypted audio samples
     * @return Decrypted audio samples
     * 
     * @details
     * Decrypts the input audio using the currently active
     * encryption system.
     * 
     * @note The system must be initialized and have an encryption system set.
     */
    std::vector<float> decrypt(const std::vector<float>& input);
    
    // Key management
    
    /**
     * @brief Set encryption key
     * 
     * @param key_id Key identifier
     * @param key_data Key data string
     * @return true if key set successfully, false otherwise
     * 
     * @details
     * Sets the encryption key for the currently active system.
     * 
     * @note The system must be initialized and have an encryption system set.
     */
    bool setKey(uint32_t key_id, const std::string& key_data);
    
    /**
     * @brief Load key from file
     * 
     * @param filename Key file path
     * @return true if key loaded successfully, false otherwise
     * 
     * @details
     * Loads encryption key from a file for the currently active system.
     */
    bool loadKeyFromFile(const std::string& filename);
    
    /**
     * @brief Save key to file
     * 
     * @param filename Key file path
     * @return true if key saved successfully, false otherwise
     * 
     * @details
     * Saves encryption key to a file for the currently active system.
     */
    bool saveKeyToFile(const std::string& filename);
    
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
    bool validateKey(const std::string& key_data);
    
    // System-specific configuration
    
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
    bool setYachtaT219Parameters(uint32_t segment_size, uint32_t scrambling_depth, float intensity);
    
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
    bool setVinsonKY57Parameters(float cvsd_rate, float quality);
    
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
    bool setGranitParameters(uint32_t segment_size, uint32_t scrambling_depth, float pilot_freq);
    
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
    bool setStanag4197Parameters(uint32_t data_rate, uint32_t ofdm_tones, uint32_t header_tones);
    
    // Status and diagnostics
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     * 
     * @details
     * Returns the initialization status of the voice encryption manager.
     */
    bool isInitialized() const;
    
    /**
     * @brief Check if encryption is active
     * 
     * @return true if encryption is active, false otherwise
     * 
     * @details
     * Returns the encryption status of the currently active system.
     */
    bool isEncryptionActive() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * voice encryption manager.
     */
    std::string getStatus() const;
    
    /**
     * @brief Get key information
     * 
     * @return Key information string
     * 
     * @details
     * Returns a string describing the current key information
     * of the currently active system.
     */
    std::string getKeyInfo() const;
    
    /**
     * @brief Get available systems
     * 
     * @return Vector of available encryption systems
     * 
     * @details
     * Returns a list of all available encryption systems.
     */
    std::vector<EncryptionSystem> getAvailableSystems() const;
    
    /**
     * @brief Get system information
     * 
     * @param system Encryption system
     * @return System information string
     * 
     * @details
     * Returns detailed information about the specified encryption system.
     */
    std::string getSystemInfo(EncryptionSystem system) const;
};

/**
 * @namespace VoiceEncryptionUtils
 * @brief Utility functions for voice encryption module
 * 
 * @details
 * This namespace contains utility functions for the voice encryption
 * module, including system detection, audio processing, and key management.
 * 
 * @since 1.0.0
 */
namespace VoiceEncryptionUtils {
    
    /**
     * @brief Detect encryption system from audio
     * 
     * @param audio Audio samples to analyze
     * @return Detected encryption system
     * 
     * @details
     * Analyzes audio samples to detect which encryption system
     * was used to encrypt them.
     * 
     * @note This is a simplified detection algorithm.
     */
    EncryptionSystem detectEncryptionSystem(const std::vector<float>& audio);
    
    /**
     * @brief Get system name
     * 
     * @param system Encryption system
     * @return System name string
     * 
     * @details
     * Returns the human-readable name of the encryption system.
     */
    std::string getSystemName(EncryptionSystem system);
    
    /**
     * @brief Get system description
     * 
     * @param system Encryption system
     * @return System description string
     * 
     * @details
     * Returns a detailed description of the encryption system.
     */
    std::string getSystemDescription(EncryptionSystem system);
    
    /**
     * @brief Get system characteristics
     * 
     * @param system Encryption system
     * @return System characteristics string
     * 
     * @details
     * Returns the audio characteristics of the encryption system.
     */
    std::string getSystemCharacteristics(EncryptionSystem system);
    
    /**
     * @brief Apply audio effects
     * 
     * @param audio Audio samples to process
     * @param system Encryption system
     * @param intensity Effect intensity (0.0-1.0)
     * 
     * @details
     * Applies audio effects characteristic of the specified
     * encryption system.
     */
    void applyAudioEffects(std::vector<float>& audio, EncryptionSystem system, float intensity);
    
    /**
     * @brief Generate test audio
     * 
     * @param system Encryption system
     * @param sample_rate Audio sample rate in Hz
     * @param duration Audio duration in seconds
     * @return Generated test audio
     * 
     * @details
     * Generates test audio characteristic of the specified
     * encryption system.
     */
    std::vector<float> generateTestAudio(EncryptionSystem system, float sample_rate, float duration);
    
    /**
     * @brief Validate audio parameters
     * 
     * @param sample_rate Audio sample rate in Hz
     * @param channels Number of audio channels
     * @return true if parameters are valid, false otherwise
     * 
     * @details
     * Validates that the audio parameters are suitable for
     * voice encryption processing.
     */
    bool validateAudioParameters(float sample_rate, uint32_t channels);
    
    /**
     * @brief Get supported sample rates
     * 
     * @return Vector of supported sample rates
     * 
     * @details
     * Returns a list of all supported audio sample rates.
     */
    std::vector<float> getSupportedSampleRates();
    
    /**
     * @brief Get supported channel counts
     * 
     * @return Vector of supported channel counts
     * 
     * @details
     * Returns a list of all supported audio channel counts.
     */
    std::vector<uint32_t> getSupportedChannelCounts();
}

} // namespace voice_encryption
} // namespace fgcom

#endif // VOICE_ENCRYPTION_H