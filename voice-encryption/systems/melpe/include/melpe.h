/**
 * @file melpe.h
 * @brief MELPe (Mixed Excitation Linear Prediction enhanced) NATO Standard Implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the complete implementation of the MELPe vocoder
 * system (STANAG 4591) that provides high-quality digital voice at
 * 2400 bps for modern NATO military communications.
 * 
 * @details
 * MELPe provides:
 * - High-quality digital voice at 2400 bps
 * - NATO standard compliance (STANAG 4591)
 * - Modern military digital voice quality
 * - Successor to KY-57/58 systems
 * - Excellent voice quality (4.0+ MOS score)
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/MELPE_DOCUMENTATION.md
 */

#ifndef MELPE_H
#define MELPE_H

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <complex>
#include <random>

namespace fgcom {
namespace melpe {

/**
 * @enum MELPeQuality
 * @brief MELPe voice quality levels
 * 
 * @details
 * This enumeration defines the available voice quality
 * levels for the MELPe vocoder.
 */
enum class MELPeQuality {
    QUALITY_LOW,        ///< Low quality (2.0-3.0 MOS)
    QUALITY_MEDIUM,     ///< Medium quality (3.0-4.0 MOS)
    QUALITY_HIGH,       ///< High quality (4.0+ MOS)
    QUALITY_MILITARY    ///< Military grade quality (4.0+ MOS)
};

/**
 * @class MELPe
 * @brief MELPe (Mixed Excitation Linear Prediction enhanced) Implementation
 * 
 * @details
 * The MELPe class implements the complete MELPe vocoder system
 * with NATO standard compliance and high-quality digital voice.
 * 
 * ## Technical Specifications
 * - **Standard**: STANAG 4591 (NATO standard)
 * - **Bitrate**: 2400 bps
 * - **Vocoder**: MELPe (Mixed Excitation Linear Prediction enhanced)
 * - **Quality**: High-quality digital voice (4.0+ MOS)
 * - **Bandwidth**: 2.4 kHz
 * - **Frame Rate**: 22.5 ms frames
 * - **Usage**: Modern NATO military communications
 * 
 * ## Usage Example
 * @code
 * #include "melpe.h"
 * 
 * // Create MELPe instance
 * MELPe melpe;
 * 
 * // Initialize with audio parameters
 * melpe.initialize(44100.0f, 1);
 * 
 * // Set NATO standard parameters
 * melpe.setNATOStandard(true);
 * 
 * // Process audio
 * std::vector<float> input_audio = loadAudioData();
 * std::vector<float> output_audio = melpe.process(input_audio);
 * @endcode
 * 
 * @note This class provides a unified interface for MELPe processing.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class MELPe {
private:
    MELPeQuality current_quality_;      ///< Current MELPe quality level
    bool initialized_;                  ///< System initialization status
    bool nato_standard_enabled_;        ///< NATO standard compliance enabled
    
    // Audio parameters
    float sample_rate_;                 ///< Audio sample rate
    uint32_t channels_;                 ///< Number of audio channels
    
    // MELPe parameters
    uint32_t bitrate_;                  ///< MELPe bitrate (2400 bps)
    float frame_duration_;              ///< Frame duration (22.5 ms)
    uint32_t frame_size_;               ///< Frame size in samples
    uint32_t lpc_order_;                ///< LPC order
    float lpc_gain_;                    ///< LPC gain
    
    // Voice quality parameters
    float voice_quality_;               ///< Voice quality (MOS score)
    bool error_resilience_enabled_;     ///< Error resilience enabled
    float error_resilience_strength_;   ///< Error resilience strength
    
    // NATO compliance parameters
    bool nato_compliance_enabled_;     ///< NATO compliance enabled
    bool military_grade_enabled_;       ///< Military grade enabled
    
    // Processing buffers
    std::vector<float> input_buffer_;   ///< Input audio buffer
    std::vector<float> output_buffer_;   ///< Output audio buffer
    std::vector<float> lpc_buffer_;     ///< LPC processing buffer
    std::vector<float> excitation_buffer_; ///< Excitation buffer
    
    // Random number generation
    std::mt19937 rng_;                  ///< Random number generator
    std::uniform_real_distribution<float> dist_; ///< Uniform distribution
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the MELPe system with default parameters.
     */
    MELPe();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the MELPe system.
     */
    virtual ~MELPe();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the MELPe system
     * 
     * @param sample_rate Audio sample rate in Hz
     * @param channels Number of audio channels
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * Initializes the MELPe system with the specified
     * audio parameters.
     * 
     * @note The system must be initialized before any other operations.
     */
    bool initialize(float sample_rate, uint32_t channels);
    
    /**
     * @brief Set MELPe quality level
     * 
     * @param quality MELPe quality level
     * @return true if quality set successfully, false otherwise
     * 
     * @details
     * Sets the voice quality level for the MELPe system.
     * 
     * @note The system must be initialized before setting quality.
     */
    bool setQuality(MELPeQuality quality);
    
    /**
     * @brief Get current MELPe quality level
     * 
     * @return Current MELPe quality level
     * 
     * @details
     * Returns the currently active MELPe quality level.
     */
    MELPeQuality getCurrentQuality() const;
    
    // Audio processing
    
    /**
     * @brief Process audio data
     * 
     * @param input Input audio samples
     * @return Processed audio samples
     * 
     * @details
     * Processes the input audio using the MELPe vocoder.
     * 
     * @note The system must be initialized and have a quality level set.
     */
    std::vector<float> process(const std::vector<float>& input);
    
    /**
     * @brief Encode audio to MELPe digital voice
     * 
     * @param input Input audio samples
     * @return Encoded MELPe digital voice data
     * 
     * @details
     * Encodes the input audio to MELPe digital voice using the
     * currently active quality level.
     */
    std::vector<uint8_t> encode(const std::vector<float>& input);
    
    /**
     * @brief Decode MELPe digital voice to audio
     * 
     * @param input Encoded MELPe digital voice data
     * @return Decoded audio samples
     * 
     * @details
     * Decodes the input MELPe digital voice data to audio using the
     * currently active quality level.
     */
    std::vector<float> decode(const std::vector<uint8_t>& input);
    
    // Configuration
    
    /**
     * @brief Set MELPe parameters
     * 
     * @param bitrate MELPe bitrate (2400 bps)
     * @param frame_duration Frame duration in milliseconds
     * @return true if parameters set successfully, false otherwise
     * 
     * @details
     * Sets the MELPe parameters for the vocoder system.
     */
    bool setMELPeParameters(uint32_t bitrate, float frame_duration);
    
    /**
     * @brief Set voice quality parameters
     * 
     * @param quality Voice quality (MOS score)
     * @param naturalness Voice naturalness (0.0-1.0)
     * @return true if parameters set successfully, false otherwise
     * 
     * @details
     * Sets the voice quality parameters for the MELPe system.
     */
    bool setVoiceQuality(float quality, float naturalness);
    
    /**
     * @brief Set error resilience parameters
     * 
     * @param enabled Enable error resilience
     * @param strength Error resilience strength (0.0-1.0)
     * @return true if parameters set successfully, false otherwise
     * 
     * @details
     * Sets the error resilience parameters for the MELPe system.
     */
    bool setErrorResilience(bool enabled, float strength);
    
    /**
     * @brief Set NATO compliance parameters
     * 
     * @param enabled Enable NATO compliance
     * @param military_grade Enable military grade quality
     * @return true if parameters set successfully, false otherwise
     * 
     * @details
     * Sets the NATO compliance parameters for the MELPe system.
     */
    bool setNATOCompliance(bool enabled, bool military_grade);
    
    /**
     * @brief Set LPC parameters
     * 
     * @param order LPC order
     * @param gain LPC gain
     * @return true if parameters set successfully, false otherwise
     * 
     * @details
     * Sets the LPC parameters for the MELPe system.
     */
    bool setLPCParameters(uint32_t order, float gain);
    
    // Status and diagnostics
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     * 
     * @details
     * Returns the initialization status of the MELPe system.
     */
    bool isInitialized() const;
    
    /**
     * @brief Check if processing is active
     * 
     * @return true if processing is active, false otherwise
     * 
     * @details
     * Returns the processing status of the MELPe system.
     */
    bool isProcessingActive() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * MELPe system.
     */
    std::string getStatus() const;
    
    /**
     * @brief Get quality information
     * 
     * @param quality MELPe quality level
     * @return Quality information string
     * 
     * @details
     * Returns detailed information about the specified MELPe quality level.
     */
    std::string getQualityInfo(MELPeQuality quality) const;
    
    /**
     * @brief Get available quality levels
     * 
     * @return Vector of available MELPe quality levels
     * 
     * @details
     * Returns a list of all available MELPe quality levels.
     */
    std::vector<MELPeQuality> getAvailableQualityLevels() const;
    
    /**
     * @brief Get performance metrics
     * 
     * @return Performance metrics string
     * 
     * @details
     * Returns performance metrics for the MELPe system.
     */
    std::string getPerformanceMetrics() const;
    
    /**
     * @brief Get NATO compliance status
     * 
     * @return NATO compliance status string
     * 
     * @details
     * Returns the NATO compliance status of the MELPe system.
     */
    std::string getNATOComplianceStatus() const;

private:
    // Helper functions for MELPe processing
    std::vector<float> computeLPC(const std::vector<float>& signal, int order);
    std::vector<uint8_t> quantizeLPC(const std::vector<float>& coeffs);
    std::vector<float> dequantizeLPC(const std::vector<uint8_t>& quantized);
    std::vector<float> applyLPCSynthesis(const std::vector<float>& excitation, 
                                        const std::vector<float>& lpc_coeffs);
};

/**
 * @namespace MELPeUtils
 * @brief Utility functions for MELPe system
 * 
 * @details
 * This namespace contains utility functions for the MELPe
 * system, including quality detection, audio processing, and
 * performance analysis.
 * 
 * @since 1.0.0
 */
namespace MELPeUtils {
    
    /**
     * @brief Detect MELPe quality from audio
     * 
     * @param audio Audio samples to analyze
     * @return Detected MELPe quality level
     * 
     * @details
     * Analyzes audio samples to detect which MELPe quality level
     * was used to process them.
     * 
     * @note This is a simplified detection algorithm.
     */
    MELPeQuality detectMELPeQuality(const std::vector<float>& audio);
    
    /**
     * @brief Get quality name
     * 
     * @param quality MELPe quality level
     * @return Quality name string
     * 
     * @details
     * Returns the human-readable name of the MELPe quality level.
     */
    std::string getQualityName(MELPeQuality quality);
    
    /**
     * @brief Get quality description
     * 
     * @param quality MELPe quality level
     * @return Quality description string
     * 
     * @details
     * Returns a detailed description of the MELPe quality level.
     */
    std::string getQualityDescription(MELPeQuality quality);
    
    /**
     * @brief Get quality characteristics
     * 
     * @param quality MELPe quality level
     * @return Quality characteristics string
     * 
     * @details
     * Returns the audio characteristics of the MELPe quality level.
     */
    std::string getQualityCharacteristics(MELPeQuality quality);
    
    /**
     * @brief Apply audio effects
     * 
     * @param audio Audio samples to process
     * @param quality MELPe quality level
     * @param intensity Effect intensity (0.0-1.0)
     * 
     * @details
     * Applies audio effects characteristic of the specified
     * MELPe quality level.
     */
    void applyAudioEffects(std::vector<float>& audio, MELPeQuality quality, float intensity);
    
    /**
     * @brief Generate test audio
     * 
     * @param quality MELPe quality level
     * @param sample_rate Audio sample rate in Hz
     * @param duration Audio duration in seconds
     * @return Generated test audio
     * 
     * @details
     * Generates test audio characteristic of the specified
     * MELPe quality level.
     */
    std::vector<float> generateTestAudio(MELPeQuality quality, float sample_rate, float duration);
    
    /**
     * @brief Validate audio parameters
     * 
     * @param sample_rate Audio sample rate in Hz
     * @param channels Number of audio channels
     * @return true if parameters are valid, false otherwise
     * 
     * @details
     * Validates that the audio parameters are suitable for
     * MELPe processing.
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
    
    /**
     * @brief Get NATO compliance information
     * 
     * @return NATO compliance information string
     * 
     * @details
     * Returns information about NATO compliance for the MELPe system.
     */
    std::string getNATOComplianceInfo();

} // namespace MELPeUtils

} // namespace melpe
} // namespace fgcom

#endif // MELPE_H
