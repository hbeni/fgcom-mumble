/**
 * @file freedv.h
 * @brief FreeDV Digital Voice System Implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the complete implementation of the FreeDV digital voice
 * system with multiple bitrate modes and OFDM-based transmission for HF
 * radio communications.
 * 
 * @details
 * FreeDV provides:
 * - Multiple bitrate modes (1600, 700, 700D, 2020, 2020B, 2020C)
 * - OFDM-based transmission for HF conditions
 * - Superior performance in challenging HF conditions
 * - High-quality digital voice encoding
 * - Built-in error correction and synchronization
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/FREEDV_DOCUMENTATION.md
 */

#ifndef FREEDV_H
#define FREEDV_H

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <complex>
#include <random>

namespace fgcom {
namespace freedv {

/**
 * @enum FreeDVMode
 * @brief Available FreeDV modes
 * 
 * @details
 * This enumeration defines all available FreeDV modes
 * with different quality/bandwidth tradeoffs.
 */
enum class FreeDVMode {
    MODE_1600,      ///< 1600 bps mode - general purpose
    MODE_700,       ///< 700 bps mode - poor HF conditions
    MODE_700D,      ///< 700D bps mode - very poor HF conditions
    MODE_2020,      ///< 2020 bps mode - high quality
    MODE_2020B,     ///< 2020B bps mode - high quality with error correction
    MODE_2020C      ///< 2020C bps mode - high quality with advanced error correction
};

/**
 * @class FreeDV
 * @brief FreeDV Digital Voice System Implementation
 * 
 * @details
 * The FreeDV class implements the complete FreeDV digital voice
 * system with multiple bitrate modes and OFDM-based transmission.
 * 
 * ## Technical Specifications
 * - **Modulation**: OFDM (Orthogonal Frequency Division Multiplexing)
 * - **Bitrate Modes**: 1600, 700, 700D, 2020, 2020B, 2020C
 * - **Frequency Range**: HF bands (3-30 MHz)
 * - **Bandwidth**: Variable by mode (1.6-2.4 kHz)
 * - **Audio Quality**: High-quality digital voice
 * - **Error Correction**: Built-in forward error correction
 * - **Synchronization**: Robust frame synchronization
 * 
 * ## Usage Example
 * @code
 * #include "freedv.h"
 * 
 * // Create FreeDV instance
 * FreeDV freedv;
 * 
 * // Initialize with audio parameters
 * freedv.initialize(44100.0f, 1);
 * 
 * // Set mode for specific conditions
 * freedv.setMode(FreeDVMode::MODE_700D); // 700D mode for poor conditions
 * 
 * // Process audio
 * std::vector<float> input_audio = loadAudioData();
 * std::vector<float> output_audio = freedv.process(input_audio);
 * @endcode
 * 
 * @note This class provides a unified interface for all FreeDV modes.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class FreeDV {
private:
    FreeDVMode current_mode_;           ///< Current FreeDV mode
    bool initialized_;                  ///< System initialization status
    
    // Audio parameters
    float sample_rate_;                 ///< Audio sample rate
    uint32_t channels_;                 ///< Number of audio channels
    
    // OFDM parameters
    uint32_t fft_size_;                 ///< FFT size for OFDM
    uint32_t num_subcarriers_;          ///< Number of OFDM subcarriers
    uint32_t guard_interval_;           ///< Guard interval samples
    float symbol_duration_;             ///< Symbol duration in seconds
    
    // Voice encoding parameters
    uint32_t bitrate_;                  ///< Current bitrate
    uint32_t frame_size_;               ///< Frame size in samples
    float frame_duration_;              ///< Frame duration in seconds
    
    // Error correction parameters
    bool error_correction_enabled_;     ///< Error correction enabled
    float error_correction_strength_;   ///< Error correction strength
    
    // Synchronization parameters
    bool synchronization_enabled_;     ///< Synchronization enabled
    float sync_threshold_;              ///< Synchronization threshold
    
    // HF optimization parameters
    bool hf_optimization_enabled_;      ///< HF optimization enabled
    float hf_optimization_strength_;    ///< HF optimization strength
    
    // Processing buffers
    std::vector<float> input_buffer_;   ///< Input audio buffer
    std::vector<float> output_buffer_;   ///< Output audio buffer
    std::vector<std::complex<float>> fft_buffer_; ///< FFT processing buffer
    
    // Random number generation
    std::mt19937 rng_;                  ///< Random number generator
    std::uniform_real_distribution<float> dist_; ///< Uniform distribution
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the FreeDV system with default parameters.
     */
    FreeDV();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the FreeDV system.
     */
    virtual ~FreeDV();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the FreeDV system
     * 
     * @param sample_rate Audio sample rate in Hz
     * @param channels Number of audio channels
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * Initializes the FreeDV system with the specified
     * audio parameters.
     * 
     * @note The system must be initialized before any other operations.
     */
    bool initialize(float sample_rate, uint32_t channels);
    
    /**
     * @brief Set FreeDV mode
     * 
     * @param mode FreeDV mode to use
     * @return true if mode set successfully, false otherwise
     * 
     * @details
     * Sets the active FreeDV mode for voice processing.
     * 
     * @note The system must be initialized before setting mode.
     */
    bool setMode(FreeDVMode mode);
    
    /**
     * @brief Get current FreeDV mode
     * 
     * @return Current FreeDV mode
     * 
     * @details
     * Returns the currently active FreeDV mode.
     */
    FreeDVMode getCurrentMode() const;
    
    // Audio processing
    
    /**
     * @brief Process audio data
     * 
     * @param input Input audio samples
     * @return Processed audio samples
     * 
     * @details
     * Processes the input audio using the currently active
     * FreeDV mode.
     * 
     * @note The system must be initialized and have a mode set.
     */
    std::vector<float> process(const std::vector<float>& input);
    
    /**
     * @brief Encode audio to digital voice
     * 
     * @param input Input audio samples
     * @return Encoded digital voice data
     * 
     * @details
     * Encodes the input audio to digital voice using the
     * currently active FreeDV mode.
     */
    std::vector<uint8_t> encode(const std::vector<float>& input);
    
    /**
     * @brief Decode digital voice to audio
     * 
     * @param input Encoded digital voice data
     * @return Decoded audio samples
     * 
     * @details
     * Decodes the input digital voice data to audio using the
     * currently active FreeDV mode.
     */
    std::vector<float> decode(const std::vector<uint8_t>& input);
    
    // Configuration
    
    /**
     * @brief Set OFDM parameters
     * 
     * @param fft_size FFT size for OFDM
     * @param num_subcarriers Number of OFDM subcarriers
     * @param guard_interval Guard interval in samples
     * @return true if parameters set successfully, false otherwise
     * 
     * @details
     * Sets the OFDM parameters for the FreeDV system.
     */
    bool setOFDMParameters(uint32_t fft_size, uint32_t num_subcarriers, uint32_t guard_interval);
    
    /**
     * @brief Set voice encoding parameters
     * 
     * @param bitrate Voice encoding bitrate
     * @param frame_size Frame size in samples
     * @return true if parameters set successfully, false otherwise
     * 
     * @details
     * Sets the voice encoding parameters for the FreeDV system.
     */
    bool setVoiceEncodingParameters(uint32_t bitrate, uint32_t frame_size);
    
    /**
     * @brief Set error correction parameters
     * 
     * @param enabled Enable error correction
     * @param strength Error correction strength (0.0-1.0)
     * @return true if parameters set successfully, false otherwise
     * 
     * @details
     * Sets the error correction parameters for the FreeDV system.
     */
    bool setErrorCorrection(bool enabled, float strength);
    
    /**
     * @brief Set synchronization parameters
     * 
     * @param enabled Enable synchronization
     * @param threshold Synchronization threshold (0.0-1.0)
     * @return true if parameters set successfully, false otherwise
     * 
     * @details
     * Sets the synchronization parameters for the FreeDV system.
     */
    bool setSynchronization(bool enabled, float threshold);
    
    /**
     * @brief Set HF optimization parameters
     * 
     * @param enabled Enable HF optimization
     * @param strength HF optimization strength (0.0-1.0)
     * @return true if parameters set successfully, false otherwise
     * 
     * @details
     * Sets the HF optimization parameters for the FreeDV system.
     */
    bool setHFParameters(bool enabled, float strength);
    
    // Status and diagnostics
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     * 
     * @details
     * Returns the initialization status of the FreeDV system.
     */
    bool isInitialized() const;
    
    /**
     * @brief Check if processing is active
     * 
     * @return true if processing is active, false otherwise
     * 
     * @details
     * Returns the processing status of the FreeDV system.
     */
    bool isProcessingActive() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * FreeDV system.
     */
    std::string getStatus() const;
    
    /**
     * @brief Get mode information
     * 
     * @param mode FreeDV mode
     * @return Mode information string
     * 
     * @details
     * Returns detailed information about the specified FreeDV mode.
     */
    std::string getModeInfo(FreeDVMode mode) const;
    
    /**
     * @brief Get available modes
     * 
     * @return Vector of available FreeDV modes
     * 
     * @details
     * Returns a list of all available FreeDV modes.
     */
    std::vector<FreeDVMode> getAvailableModes() const;
    
    /**
     * @brief Get performance metrics
     * 
     * @return Performance metrics string
     * 
     * @details
     * Returns performance metrics for the FreeDV system.
     */
    std::string getPerformanceMetrics() const;
};

/**
 * @namespace FreeDVUtils
 * @brief Utility functions for FreeDV system
 * 
 * @details
 * This namespace contains utility functions for the FreeDV
 * system, including mode detection, audio processing, and
 * performance analysis.
 * 
 * @since 1.0.0
 */
namespace FreeDVUtils {
    
    /**
     * @brief Detect FreeDV mode from audio
     * 
     * @param audio Audio samples to analyze
     * @return Detected FreeDV mode
     * 
     * @details
     * Analyzes audio samples to detect which FreeDV mode
     * was used to process them.
     * 
     * @note This is a simplified detection algorithm.
     */
    FreeDVMode detectFreeDVMode(const std::vector<float>& audio);
    
    /**
     * @brief Get mode name
     * 
     * @param mode FreeDV mode
     * @return Mode name string
     * 
     * @details
     * Returns the human-readable name of the FreeDV mode.
     */
    std::string getModeName(FreeDVMode mode);
    
    /**
     * @brief Get mode description
     * 
     * @param mode FreeDV mode
     * @return Mode description string
     * 
     * @details
     * Returns a detailed description of the FreeDV mode.
     */
    std::string getModeDescription(FreeDVMode mode);
    
    /**
     * @brief Get mode characteristics
     * 
     * @param mode FreeDV mode
     * @return Mode characteristics string
     * 
     * @details
     * Returns the audio characteristics of the FreeDV mode.
     */
    std::string getModeCharacteristics(FreeDVMode mode);
    
    /**
     * @brief Apply audio effects
     * 
     * @param audio Audio samples to process
     * @param mode FreeDV mode
     * @param intensity Effect intensity (0.0-1.0)
     * 
     * @details
     * Applies audio effects characteristic of the specified
     * FreeDV mode.
     */
    void applyAudioEffects(std::vector<float>& audio, FreeDVMode mode, float intensity);
    
    /**
     * @brief Generate test audio
     * 
     * @param mode FreeDV mode
     * @param sample_rate Audio sample rate in Hz
     * @param duration Audio duration in seconds
     * @return Generated test audio
     * 
     * @details
     * Generates test audio characteristic of the specified
     * FreeDV mode.
     */
    std::vector<float> generateTestAudio(FreeDVMode mode, float sample_rate, float duration);
    
    /**
     * @brief Validate audio parameters
     * 
     * @param sample_rate Audio sample rate in Hz
     * @param channels Number of audio channels
     * @return true if parameters are valid, false otherwise
     * 
     * @details
     * Validates that the audio parameters are suitable for
     * FreeDV processing.
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
};

} // namespace freedv
} // namespace fgcom

#endif // FREEDV_H
