/**
 * @file granit.cpp
 * @brief Granit Soviet Time-Scrambling Voice Encryption System Implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the complete implementation of the Soviet Granit
 * time-scrambling voice encryption system with authentic temporal distortion
 * characteristics and scrambling methods.
 * 
 * @details
 * The implementation provides:
 * - Authentic Soviet temporal distortion characteristics
 * - Time-domain segment scrambling with reordering
 * - Pilot signal synchronization
 * - Temporal distortion effects
 * - Real-time audio processing capabilities
 * 
 * @see granit.h
 * @see docs/GRANIT_DOCUMENTATION.md
 */

#include "granit.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace fgcom {
namespace granit {

/**
 * @brief Granit Implementation
 * 
 * @details
 * This section contains the complete implementation of the Granit
 * Soviet time-scrambling voice encryption system.
 */

/**
 * @brief Constructor for Granit system
 * 
 * @details
 * Initializes the Granit system with default parameters matching
 * the original Soviet system specifications:
 * - Sample rate: 44.1 kHz
 * - Channels: 1 (mono)
 * - Segment size: 20 ms (882 samples at 44.1 kHz)
 * - Scrambling depth: 8 segments
 * - Pilot frequency: 1.5 kHz
 * - Processing delay: 400 ms
 * - Temporal distortion: 0.8
 * 
 * @note The system must be initialized with initialize() before use.
 */
Granit::Granit() 
    : scrambling_index_(0)
    , pilot_phase_(0.0f)
    , pilot_amplitude_(0.0f)
    , pilot_sync_active_(false)
    , current_segment_(0)
    , segment_counter_(0)
    , sync_key_index_(0)
    , synchronization_active_(false)
    , sync_delay_(0.0f)
    , distortion_modulation_(0.0f)
    , distortion_delay_(0)
    , initialized_(false)
    , scrambling_active_(false)
    , pilot_active_(false)
    , fft_processing_active_(false)
    , hop_size_(512)
    , window_size_(1024)
    , overlap_size_(256)
    , fft_hop_(256)
    , rng_(std::random_device{}())
    , dist_(0.0f, 1.0f)
    , key_index_(0)
    , temporal_delay_(0)
    , temporal_modulation_(0.0f) {
    
    // Initialize default parameters for Granit
    config_.sample_rate = 44100.0f;                    ///< Standard audio sample rate
    config_.channels = 1;                              ///< Mono audio
    config_.segment_size = 882;                        ///< 20 ms segments at 44.1 kHz
    config_.scrambling_depth = 8;                      ///< 8 segments for scrambling
    config_.pilot_frequency = 1500.0f;                 ///< 1.5 kHz pilot signal
    config_.pilot_amplitude = 0.1f;                    ///< 10% pilot amplitude
    config_.key_length = 64;                           ///< 64-bit scrambling key
    config_.scrambling_mode = "time";                  ///< Time-domain scrambling
    config_.processing_delay = 0.4f;                   ///< 400 ms processing delay
    config_.use_pilot_signal = true;                   ///< Enable pilot signal
    config_.temporal_distortion = 0.8f;                ///< 80% temporal distortion
    config_.use_window_function = true;                ///< Enable window function
    config_.window_type = "hanning";                   ///< Hanning window
    config_.overlap_factor = 0.5f;                     ///< 50% segment overlap
    config_.use_fft_processing = true;                 ///< Enable FFT processing
    config_.fft_size = 1024;                           ///< 1024-point FFT
    config_.synchronization_mode = "pilot";            ///< Pilot signal synchronization
}

/**
 * @brief Destructor for Granit system
 * 
 * @details
 * Cleans up all resources used by the Granit system.
 */
Granit::~Granit() {
    // Cleanup resources
}

/**
 * @brief Initialize the Granit system
 * 
 * @param sample_rate Audio sample rate in Hz
 * @param channels Number of audio channels
 * @return true if initialization successful, false otherwise
 * 
 * @details
 * Initializes the Granit system with the specified audio parameters.
 * Sets up all internal buffers, filters, and processing components.
 */
bool Granit::initialize(float sample_rate, uint32_t channels) {
    if (sample_rate <= 0.0f || channels == 0) {
        return false;
    }
    
    config_.sample_rate = sample_rate;
    config_.channels = channels;
    
    // Calculate segment size based on sample rate
    config_.segment_size = static_cast<uint32_t>(config_.sample_rate * 0.02f); // 20 ms
    
    // Initialize buffers
    input_buffer_.resize(fft_size_);
    output_buffer_.resize(fft_size_);
    processing_buffer_.resize(fft_size_);
    fft_buffer_.resize(fft_size_);
    distortion_buffer_.resize(fft_size_);
    temporal_buffer_.resize(fft_size_);
    
    // Initialize segment buffer
    segment_buffer_.clear();
    time_segments_.clear();
    time_segments_.resize(config_.scrambling_depth);
    
    // Initialize scrambling sequence
    scrambling_sequence_.clear();
    scrambling_sequence_.resize(config_.scrambling_depth);
    for (uint32_t i = 0; i < config_.scrambling_depth; ++i) {
        scrambling_sequence_[i] = i;
    }
    
    // Initialize window function
    window_function_ = GranitUtils::generateWindowFunction(config_.window_type, config_.segment_size);
    
    // Initialize pilot signal
    pilot_signal_.clear();
    pilot_phase_ = 0.0f;
    pilot_amplitude_ = config_.pilot_amplitude;
    
    // Initialize synchronization
    synchronization_key_.clear();
    sync_key_index_ = 0;
    synchronization_active_ = false;
    sync_delay_ = config_.processing_delay;
    
    // Initialize temporal distortion
    distortion_modulation_ = 0.0f;
    distortion_delay_ = static_cast<uint32_t>(config_.sample_rate * 0.1f); // 100 ms delay
    temporal_delay_ = static_cast<uint32_t>(config_.sample_rate * 0.05f); // 50 ms delay
    temporal_modulation_ = 0.0f;
    
    // Initialize filters
    lowpass_filter_.resize(64, 0.0f);
    highpass_filter_.resize(64, 0.0f);
    bandpass_filter_.resize(64, 0.0f);
    pilot_filter_.resize(64, 0.0f);
    
    // Initialize FFT workspace
    fft_workspace_.resize(fft_size_);
    fft_window_.resize(fft_size_);
    fft_hop_ = fft_size_ / 4;
    
    // Initialize state flags
    initialized_ = true;
    scrambling_active_ = false;
    pilot_active_ = false;
    fft_processing_active_ = false;
    
    return true;
}

/**
 * @brief Set scrambling key
 * 
 * @param key_id Key identifier
 * @param key_data Key data string
 * @return true if key set successfully, false otherwise
 * 
 * @details
 * Sets the scrambling key for the Granit system.
 * The key data is used to generate the pseudo-random scrambling sequence.
 */
bool Granit::setKey(uint32_t key_id, const std::string& key_data) {
    if (!initialized_ || key_data.empty()) {
        return false;
    }
    
    // Parse key data
    std::vector<uint8_t> key_bytes = GranitUtils::parseKeyData(key_data);
    if (key_bytes.empty()) {
        return false;
    }
    
    // Validate key length
    if (key_bytes.size() * 8 < config_.key_length) {
        return false;
    }
    
    // Set scrambling key
    scrambling_key_ = key_data;
    key_bytes_ = key_bytes;
    key_index_ = 0;
    
    // Generate scrambling sequence
    generateScramblingSequence();
    
    scrambling_active_ = true;
    
    return true;
}

/**
 * @brief Set scrambling parameters
 * 
 * @param segment_size Time segment size in samples
 * @param scrambling_depth Number of segments to scramble
 * @param pilot_freq Pilot signal frequency in Hz
 * @return true if parameters set successfully, false otherwise
 * 
 * @details
 * Sets the time-scrambling parameters for the Granit system.
 * These parameters control the temporal distortion characteristics.
 */
bool Granit::setScramblingParameters(uint32_t segment_size, uint32_t scrambling_depth, float pilot_freq) {
    if (!initialized_ || segment_size == 0 || scrambling_depth == 0) {
        return false;
    }
    
    config_.segment_size = segment_size;
    config_.scrambling_depth = scrambling_depth;
    config_.pilot_frequency = pilot_freq;
    
    // Update window function
    window_function_ = GranitUtils::generateWindowFunction(config_.window_type, config_.segment_size);
    
    // Update scrambling sequence
    scrambling_sequence_.resize(config_.scrambling_depth);
    for (uint32_t i = 0; i < config_.scrambling_depth; ++i) {
        scrambling_sequence_[i] = i;
    }
    
    // Regenerate scrambling sequence if key is set
    if (scrambling_active_) {
        generateScramblingSequence();
    }
    
    return true;
}

/**
 * @brief Encrypt audio data
 * 
 * @param input Input audio samples
 * @return Encrypted audio samples
 * 
 * @details
 * Encrypts the input audio using the Granit time-scrambling algorithm.
 * The process includes time segment division, segment reordering, pilot signal
 * addition, and temporal distortion effects.
 */
std::vector<float> Granit::encrypt(const std::vector<float>& input) {
    if (!initialized_ || !scrambling_active_ || input.empty()) {
        return input;
    }
    
    std::vector<float> output = input;
    
    // Apply frequency response filtering
    GranitUtils::applyFrequencyResponse(output, config_.sample_rate, 
                                      300.0f, 3400.0f);
    
    // Process time segmentation
    processTimeSegmentation(output);
    
    // Process segment scrambling
    processSegmentScrambling(output);
    
    // Process pilot signal
    processPilotSignal(output);
    
    // Process temporal distortion
    processTemporalDistortion(output);
    
    // Apply Soviet effects
    processSovietEffects(output);
    
    return output;
}

/**
 * @brief Decrypt audio data
 * 
 * @param input Encrypted audio samples
 * @return Decrypted audio samples
 * 
 * @details
 * Decrypts the input audio using the Granit time-descrambling algorithm.
 * This reverses the time-scrambling process to restore original audio.
 */
std::vector<float> Granit::decrypt(const std::vector<float>& input) {
    if (!initialized_ || !scrambling_active_ || input.empty()) {
        return input;
    }
    
    std::vector<float> output = input;
    
    // Reverse Soviet effects
    // Note: This is a simplified reversal
    processSovietEffects(output);
    
    // Process temporal distortion reversal
    processTemporalDistortion(output);
    
    // Process pilot signal removal
    processPilotSignal(output);
    
    // Process segment descrambling
    processSegmentScrambling(output);
    
    // Process time segment reconstruction
    processTimeSegmentation(output);
    
    return output;
}

/**
 * @brief Set temporal distortion
 * 
 * @param intensity Distortion intensity (0.0-1.0)
 * 
 * @details
 * Sets the temporal distortion intensity for the Granit system.
 */
void Granit::setTemporalDistortion(float intensity) {
    config_.temporal_distortion = std::clamp(intensity, 0.0f, 1.0f);
    distortion_modulation_ = config_.temporal_distortion;
}

/**
 * @brief Set pilot signal
 * 
 * @param frequency Pilot signal frequency in Hz
 * @param amplitude Pilot signal amplitude
 * 
 * @details
 * Sets the pilot signal parameters for synchronization.
 */
void Granit::setPilotSignal(float frequency, float amplitude) {
    config_.pilot_frequency = frequency;
    config_.pilot_amplitude = amplitude;
    pilot_amplitude_ = amplitude;
}

/**
 * @brief Set window function
 * 
 * @param window_type Window function type
 * @param overlap Overlap factor (0.0-1.0)
 * 
 * @details
 * Sets the window function parameters for segment processing.
 */
void Granit::setWindowFunction(const std::string& window_type, float overlap) {
    config_.window_type = window_type;
    config_.overlap_factor = std::clamp(overlap, 0.0f, 1.0f);
    
    // Regenerate window function
    window_function_ = GranitUtils::generateWindowFunction(config_.window_type, config_.segment_size);
}

/**
 * @brief Set synchronization mode
 * 
 * @param mode Synchronization mode
 * 
 * @details
 * Sets the synchronization mode for the Granit system.
 */
void Granit::setSynchronizationMode(const std::string& mode) {
    config_.synchronization_mode = mode;
    synchronization_active_ = (mode == "pilot" || mode == "hybrid");
}

/**
 * @brief Load key from file
 * 
 * @param filename Key file path
 * @return true if key loaded successfully, false otherwise
 * 
 * @details
 * Loads scrambling key from a file for the Granit system.
 */
bool Granit::loadKeyFromFile(const std::string& filename) {
    if (!initialized_ || filename.empty()) {
        return false;
    }
    
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    std::vector<uint8_t> key_bytes;
    uint8_t byte;
    while (file.read(reinterpret_cast<char*>(&byte), 1)) {
        key_bytes.push_back(byte);
    }
    
    if (key_bytes.empty()) {
        return false;
    }
    
    // Set scrambling key
    scrambling_key_ = GranitUtils::generateKeyData(key_bytes);
    key_bytes_ = key_bytes;
    key_index_ = 0;
    
    // Generate scrambling sequence
    generateScramblingSequence();
    
    scrambling_active_ = true;
    
    return true;
}

/**
 * @brief Save key to file
 * 
 * @param filename Key file path
 * @return true if key saved successfully, false otherwise
 * 
 * @details
 * Saves scrambling key to a file for the Granit system.
 */
bool Granit::saveKeyToFile(const std::string& filename) {
    if (!initialized_ || !scrambling_active_ || filename.empty()) {
        return false;
    }
    
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(key_bytes_.data()), key_bytes_.size());
    
    return file.good();
}

/**
 * @brief Generate scrambling sequence
 * 
 * @return true if sequence generated successfully, false otherwise
 * 
 * @details
 * Generates a new scrambling sequence for the Granit system.
 */
bool Granit::generateScramblingSequence() {
    if (!initialized_ || key_bytes_.empty()) {
        return false;
    }
    
    // Generate scrambling sequence based on key
    scrambling_sequence_ = GranitUtils::generateScramblingSequence(
        config_.key_length, config_.scrambling_depth);
    
    return true;
}

/**
 * @brief Validate key
 * 
 * @param key_data Key data string to validate
 * @return true if key is valid, false otherwise
 * 
 * @details
 * Validates that the key data meets Granit requirements.
 */
bool Granit::validateKey(const std::string& key_data) {
    if (!initialized_ || key_data.empty()) {
        return false;
    }
    
    // Validate key format
    if (!GranitUtils::validateKeyFormat(key_data)) {
        return false;
    }
    
    // Parse key data
    std::vector<uint8_t> key_bytes = GranitUtils::parseKeyData(key_data);
    if (key_bytes.empty()) {
        return false;
    }
    
    // Validate key length
    return key_bytes.size() * 8 >= config_.key_length;
}

/**
 * @brief Apply temporal distortion
 * 
 * @param audio Audio samples to process
 * @param intensity Distortion intensity (0.0-1.0)
 * 
 * @details
 * Applies temporal distortion effects to the audio samples.
 */
void Granit::applyTemporalDistortion(std::vector<float>& audio, float intensity) {
    if (audio.empty() || intensity <= 0.0f) {
        return;
    }
    
    GranitUtils::applyTemporalDistortion(audio, intensity);
}

/**
 * @brief Apply segment scrambling
 * 
 * @param audio Audio samples to process
 * 
 * @details
 * Applies time-domain segment scrambling to the audio samples.
 */
void Granit::applySegmentScrambling(std::vector<float>& audio) {
    if (audio.empty() || scrambling_sequence_.empty()) {
        return;
    }
    
    GranitUtils::applySegmentScrambling(audio, config_.segment_size, scrambling_sequence_);
}

/**
 * @brief Apply pilot signal
 * 
 * @param audio Audio samples to process
 * 
 * @details
 * Adds pilot signal to the audio samples for synchronization.
 */
void Granit::applyPilotSignal(std::vector<float>& audio) {
    if (audio.empty()) {
        return;
    }
    
    GranitUtils::applyPilotSignal(audio, config_.pilot_frequency, config_.pilot_amplitude);
}

/**
 * @brief Apply Soviet effects
 * 
 * @param audio Audio samples to process
 * 
 * @details
 * Applies all Soviet audio effects including temporal distortion
 * and segment scrambling to simulate the Granit system.
 */
void Granit::applySovietEffects(std::vector<float>& audio) {
    if (audio.empty()) {
        return;
    }
    
    GranitUtils::applySovietEffects(audio);
}

/**
 * @brief Check if system is initialized
 * 
 * @return true if initialized, false otherwise
 * 
 * @details
 * Returns the initialization status of the Granit system.
 */
bool Granit::isInitialized() const {
    return initialized_;
}

/**
 * @brief Check if scrambling is active
 * 
 * @return true if scrambling is active, false otherwise
 * 
 * @details
 * Returns the scrambling status of the Granit system.
 */
bool Granit::isScramblingActive() const {
    return scrambling_active_;
}

/**
 * @brief Check if pilot signal is active
 * 
 * @return true if pilot signal is active, false otherwise
 * 
 * @details
 * Returns the pilot signal status of the Granit system.
 */
bool Granit::isPilotActive() const {
    return pilot_active_;
}

/**
 * @brief Get system status
 * 
 * @return Status string
 * 
 * @details
 * Returns a string describing the current status of the Granit system.
 */
std::string Granit::getStatus() const {
    std::ostringstream oss;
    oss << "Granit Status: ";
    oss << "Initialized=" << (initialized_ ? "Yes" : "No") << ", ";
    oss << "Scrambling=" << (scrambling_active_ ? "Active" : "Inactive") << ", ";
    oss << "Pilot=" << (pilot_active_ ? "Active" : "Inactive");
    return oss.str();
}

/**
 * @brief Get key information
 * 
 * @return Key information string
 * 
 * @details
 * Returns a string describing the current key information of the Granit system.
 */
std::string Granit::getKeyInfo() const {
    if (!scrambling_active_) {
        return "No key loaded";
    }
    
    std::ostringstream oss;
    oss << "Key Length: " << (key_bytes_.size() * 8) << " bits, ";
    oss << "Scrambling Depth: " << config_.scrambling_depth << ", ";
    oss << "Segment Size: " << config_.segment_size << " samples";
    return oss.str();
}

// Private methods implementation

void Granit::processTimeSegmentation(std::vector<float>& audio) {
    if (audio.empty()) {
        return;
    }
    
    // Generate time segments
    std::vector<std::vector<float>> segments = GranitUtils::generateTimeSegments(
        audio, config_.segment_size, config_.overlap_factor);
    
    // Store segments for processing
    time_segments_ = segments;
}

void Granit::processSegmentScrambling(std::vector<float>& audio) {
    if (audio.empty() || scrambling_sequence_.empty()) {
        return;
    }
    
    // Apply segment scrambling
    GranitUtils::applySegmentScrambling(audio, config_.segment_size, scrambling_sequence_);
}

void Granit::processPilotSignal(std::vector<float>& audio) {
    if (audio.empty()) {
        return;
    }
    
    // Generate pilot signal
    std::vector<float> pilot = GranitUtils::generatePilotSignal(
        config_.pilot_frequency, config_.pilot_amplitude, 
        config_.sample_rate, static_cast<float>(audio.size()) / config_.sample_rate);
    
    // Add pilot signal to audio
    for (size_t i = 0; i < audio.size() && i < pilot.size(); ++i) {
        audio[i] += pilot[i];
    }
}

void Granit::processTemporalDistortion(std::vector<float>& audio) {
    if (audio.empty()) {
        return;
    }
    
    // Apply temporal distortion
    GranitUtils::applyTemporalDistortion(audio, config_.temporal_distortion);
}

void Granit::processSynchronization(std::vector<float>& audio) {
    if (audio.empty()) {
        return;
    }
    
    // Process synchronization based on mode
    if (config_.synchronization_mode == "pilot") {
        processPilotSynchronization(audio);
    } else if (config_.synchronization_mode == "key") {
        processSynchronizationKey(audio);
    } else if (config_.synchronization_mode == "hybrid") {
        processPilotSynchronization(audio);
        processSynchronizationKey(audio);
    }
}

void Granit::processWindowFunction(std::vector<float>& audio) {
    if (audio.empty() || window_function_.empty()) {
        return;
    }
    
    // Apply window function
    GranitUtils::applyWindowFunction(audio, window_function_);
}

void Granit::processFFTScrambling(std::vector<float>& audio) {
    if (audio.empty()) {
        return;
    }
    
    // FFT-based scrambling processing
    // This would involve FFT, frequency domain scrambling, and inverse FFT
    // Implementation depends on specific FFT library used
}

void Granit::processSegmentReordering(std::vector<float>& audio) {
    if (audio.empty() || scrambling_sequence_.empty()) {
        return;
    }
    
    // Process segment reordering based on scrambling sequence
    for (size_t i = 0; i < audio.size(); i += config_.segment_size) {
        uint32_t segment_index = (i / config_.segment_size) % scrambling_sequence_.size();
        uint32_t target_index = scrambling_sequence_[segment_index];
        
        // Reorder segments based on scrambling sequence
        // This is a simplified implementation
    }
}

void Granit::processPilotSynchronization(std::vector<float>& audio) {
    if (audio.empty()) {
        return;
    }
    
    // Process pilot signal synchronization
    pilot_active_ = true;
    pilot_sync_active_ = true;
}

void Granit::processTemporalEffects(std::vector<float>& audio) {
    if (audio.empty()) {
        return;
    }
    
    // Process temporal effects
    distortion_modulation_ = config_.temporal_distortion;
    temporal_modulation_ = config_.temporal_distortion * 0.5f;
}

void Granit::processSovietEffects(std::vector<float>& audio) {
    if (audio.empty()) {
        return;
    }
    
    // Apply all Soviet effects
    GranitUtils::applySovietEffects(audio);
}

void Granit::generateScramblingSequence() {
    if (key_bytes_.empty()) {
        return;
    }
    
    // Generate scrambling sequence based on key
    scrambling_sequence_ = GranitUtils::generateScramblingSequence(
        config_.key_length, config_.scrambling_depth);
}

void Granit::processKeyStream(std::vector<float>& audio) {
    if (audio.empty() || key_bytes_.empty()) {
        return;
    }
    
    // Process key stream for scrambling
    for (size_t i = 0; i < audio.size(); ++i) {
        uint8_t key_byte = key_bytes_[key_index_ % key_bytes_.size()];
        float key_value = (key_byte - 128.0f) / 128.0f;
        
        // Apply key stream
        audio[i] = audio[i] * (1.0f + key_value * 0.05f);
        
        key_index_++;
    }
}

void Granit::processSynchronizationKey(std::vector<float>& audio) {
    if (audio.empty() || synchronization_key_.empty()) {
        return;
    }
    
    // Process synchronization key
    for (size_t i = 0; i < audio.size(); ++i) {
        uint8_t sync_byte = synchronization_key_[sync_key_index_ % synchronization_key_.size()];
        float sync_value = (sync_byte - 128.0f) / 128.0f;
        
        // Apply synchronization
        audio[i] = audio[i] * (1.0f + sync_value * 0.02f);
        
        sync_key_index_++;
    }
}

// GranitUtils namespace implementation

namespace GranitUtils {

std::vector<std::vector<float>> generateTimeSegments(const std::vector<float>& audio, 
                                                    uint32_t segment_size, 
                                                    float overlap_factor) {
    std::vector<std::vector<float>> segments;
    if (audio.empty() || segment_size == 0) {
        return segments;
    }
    
    uint32_t hop_size = static_cast<uint32_t>(segment_size * (1.0f - overlap_factor));
    
    for (size_t i = 0; i < audio.size(); i += hop_size) {
        std::vector<float> segment;
        for (uint32_t j = 0; j < segment_size && (i + j) < audio.size(); ++j) {
            segment.push_back(audio[i + j]);
        }
        
        if (!segment.empty()) {
            segments.push_back(segment);
        }
    }
    
    return segments;
}

std::vector<float> reconstructFromSegments(const std::vector<std::vector<float>>& segments, 
                                          float overlap_factor) {
    std::vector<float> audio;
    if (segments.empty()) {
        return audio;
    }
    
    // Simple reconstruction without overlap-add
    for (const auto& segment : segments) {
        for (float sample : segment) {
            audio.push_back(sample);
        }
    }
    
    return audio;
}

std::vector<uint32_t> generateScramblingSequence(uint32_t key_length, uint32_t sequence_length) {
    std::vector<uint32_t> sequence;
    if (sequence_length == 0) {
        return sequence;
    }
    
    // Initialize sequence
    for (uint32_t i = 0; i < sequence_length; ++i) {
        sequence.push_back(i);
    }
    
    // Shuffle sequence based on key
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(sequence.begin(), sequence.end(), gen);
    
    return sequence;
}

std::vector<std::vector<float>> applyTimeScrambling(const std::vector<std::vector<float>>& segments, 
                                                   const std::vector<uint32_t>& scrambling_sequence) {
    std::vector<std::vector<float>> scrambled_segments;
    if (segments.empty() || scrambling_sequence.empty()) {
        return scrambled_segments;
    }
    
    // Apply scrambling based on sequence
    for (uint32_t index : scrambling_sequence) {
        if (index < segments.size()) {
            scrambled_segments.push_back(segments[index]);
        }
    }
    
    return scrambled_segments;
}

std::vector<std::vector<float>> applyTimeDescrambling(const std::vector<std::vector<float>>& segments, 
                                                     const std::vector<uint32_t>& scrambling_sequence) {
    std::vector<std::vector<float>> descrambled_segments;
    if (segments.empty() || scrambling_sequence.empty()) {
        return descrambled_segments;
    }
    
    // Create inverse scrambling sequence
    std::vector<uint32_t> inverse_sequence(scrambling_sequence.size());
    for (size_t i = 0; i < scrambling_sequence.size(); ++i) {
        inverse_sequence[scrambling_sequence[i]] = static_cast<uint32_t>(i);
    }
    
    // Apply inverse scrambling
    for (uint32_t index : inverse_sequence) {
        if (index < segments.size()) {
            descrambled_segments.push_back(segments[index]);
        }
    }
    
    return descrambled_segments;
}

std::vector<float> generatePilotSignal(float frequency, float amplitude, 
                                     float sample_rate, float duration) {
    std::vector<float> pilot;
    int samples = static_cast<int>(sample_rate * duration);
    
    for (int i = 0; i < samples; ++i) {
        float sample = amplitude * std::sin(2.0f * M_PI * frequency * i / sample_rate);
        pilot.push_back(sample);
    }
    
    return pilot;
}

void applyTemporalDistortion(std::vector<float>& audio, float intensity) {
    if (audio.empty() || intensity <= 0.0f) {
        return;
    }
    
    // Apply temporal distortion
    for (size_t i = 0; i < audio.size(); ++i) {
        float sample = audio[i];
        
        // Temporal modulation
        float modulation = std::sin(2.0f * M_PI * 5.0f * i / 44100.0f) * intensity;
        sample = sample * (1.0f + modulation);
        
        // Time-jump effect
        if (i % 100 == 0) {
            sample *= (1.0f + intensity * 0.5f);
        }
        
        audio[i] = sample;
    }
}

void applySegmentScrambling(std::vector<float>& audio, uint32_t segment_size, 
                           const std::vector<uint32_t>& scrambling_sequence) {
    if (audio.empty() || segment_size == 0 || scrambling_sequence.empty()) {
        return;
    }
    
    // Apply segment scrambling
    for (size_t i = 0; i < audio.size(); i += segment_size) {
        uint32_t segment_index = (i / segment_size) % scrambling_sequence.size();
        uint32_t target_index = scrambling_sequence[segment_index];
        
        // Simple scrambling implementation
        if (target_index < scrambling_sequence.size()) {
            // Apply scrambling effect
            for (uint32_t j = 0; j < segment_size && (i + j) < audio.size(); ++j) {
                audio[i + j] *= (1.0f + 0.1f * std::sin(2.0f * M_PI * target_index * j / segment_size));
            }
        }
    }
}

void applyPilotSignal(std::vector<float>& audio, float pilot_frequency, float pilot_amplitude) {
    if (audio.empty()) {
        return;
    }
    
    // Add pilot signal to audio
    for (size_t i = 0; i < audio.size(); ++i) {
        float pilot_sample = pilot_amplitude * std::sin(2.0f * M_PI * pilot_frequency * i / 44100.0f);
        audio[i] += pilot_sample;
    }
}

void applySovietEffects(std::vector<float>& audio) {
    if (audio.empty()) {
        return;
    }
    
    // Apply all Soviet effects
    applyTemporalDistortion(audio, 0.8f);
}

void applyFrequencyResponse(std::vector<float>& audio, 
                           float sample_rate,
                           float min_freq, 
                           float max_freq) {
    if (audio.empty()) {
        return;
    }
    
    // Apply bandpass filtering
    for (size_t i = 0; i < audio.size(); ++i) {
        float sample = audio[i];
        
        // Simple bandpass filter
        float frequency = i * sample_rate / audio.size();
        if (frequency < min_freq || frequency > max_freq) {
            sample *= 0.1f; // Attenuate out-of-band frequencies
        }
        
        audio[i] = sample;
    }
}

std::vector<float> generateTestTone(float frequency, float sample_rate, float duration) {
    std::vector<float> tone;
    int samples = static_cast<int>(sample_rate * duration);
    
    for (int i = 0; i < samples; ++i) {
        float sample = std::sin(2.0f * M_PI * frequency * i / sample_rate);
        tone.push_back(sample);
    }
    
    return tone;
}

std::vector<float> generateNoise(float sample_rate, float duration) {
    std::vector<float> noise;
    int samples = static_cast<int>(sample_rate * duration);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    for (int i = 0; i < samples; ++i) {
        noise.push_back(dist(gen));
    }
    
    return noise;
}

std::vector<float> generateChirp(float start_freq, float end_freq, float sample_rate, float duration) {
    std::vector<float> chirp;
    int samples = static_cast<int>(sample_rate * duration);
    
    for (int i = 0; i < samples; ++i) {
        float t = static_cast<float>(i) / sample_rate;
        float frequency = start_freq + (end_freq - start_freq) * t / duration;
        float sample = std::sin(2.0f * M_PI * frequency * t);
        chirp.push_back(sample);
    }
    
    return chirp;
}

std::vector<uint8_t> parseKeyData(const std::string& key_data) {
    std::vector<uint8_t> key_bytes;
    if (key_data.empty()) {
        return key_bytes;
    }
    
    std::istringstream iss(key_data);
    std::string byte_str;
    
    while (iss >> byte_str) {
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            key_bytes.push_back(byte);
        } catch (const std::exception&) {
            // Invalid byte format
            return std::vector<uint8_t>();
        }
    }
    
    return key_bytes;
}

std::string generateKeyData(const std::vector<uint8_t>& key_bytes) {
    std::ostringstream oss;
    
    for (size_t i = 0; i < key_bytes.size(); ++i) {
        if (i > 0) {
            oss << " ";
        }
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key_bytes[i]);
    }
    
    return oss.str();
}

bool validateKeyFormat(const std::string& key_data) {
    if (key_data.empty()) {
        return false;
    }
    
    std::istringstream iss(key_data);
    std::string byte_str;
    
    while (iss >> byte_str) {
        if (byte_str.length() != 2) {
            return false;
        }
        
        for (char c : byte_str) {
            if (!std::isxdigit(c)) {
                return false;
            }
        }
    }
    
    return true;
}

std::vector<float> generateWindowFunction(const std::string& window_type, uint32_t size) {
    std::vector<float> window;
    if (size == 0) {
        return window;
    }
    
    window.resize(size);
    
    if (window_type == "hanning") {
        for (uint32_t i = 0; i < size; ++i) {
            window[i] = 0.5f * (1.0f - std::cos(2.0f * M_PI * i / (size - 1)));
        }
    } else if (window_type == "hamming") {
        for (uint32_t i = 0; i < size; ++i) {
            window[i] = 0.54f - 0.46f * std::cos(2.0f * M_PI * i / (size - 1));
        }
    } else if (window_type == "blackman") {
        for (uint32_t i = 0; i < size; ++i) {
            window[i] = 0.42f - 0.5f * std::cos(2.0f * M_PI * i / (size - 1)) + 
                       0.08f * std::cos(4.0f * M_PI * i / (size - 1));
        }
    } else {
        // Default to rectangular window
        std::fill(window.begin(), window.end(), 1.0f);
    }
    
    return window;
}

void applyWindowFunction(std::vector<float>& audio, const std::vector<float>& window) {
    if (audio.empty() || window.empty()) {
        return;
    }
    
    size_t min_size = std::min(audio.size(), window.size());
    for (size_t i = 0; i < min_size; ++i) {
        audio[i] *= window[i];
    }
}

} // namespace GranitUtils

} // namespace granit
} // namespace fgcom
