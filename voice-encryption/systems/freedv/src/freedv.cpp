/**
 * @file freedv.cpp
 * @brief FreeDV Voice Encryption System Implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of the FreeDV voice encryption system.
 */

#include "freedv.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace fgcom {
namespace freedv {

// Constructor
FreeDV::FreeDV() 
    : current_mode_(FreeDVMode::MODE_1600)
    , initialized_(false)
    , sample_rate_(8000.0f)
    , channels_(1)
    , fft_size_(1024)
    , num_subcarriers_(64)
    , guard_interval_(128)
    , symbol_duration_(0.1f)
    , bitrate_(1600)
    , frame_size_(1024)
    , frame_duration_(0.1f)
    , encryption_(std::make_unique<crypto::ChaCha20Poly1305>(crypto::SecurityLevel::STANDARD))
    , encryption_enabled_(false)
    , encryption_key_(16, 0) {
}

// Destructor
FreeDV::~FreeDV() {
}

// Initialize the FreeDV system
bool FreeDV::initialize(float sample_rate, uint32_t channels) {
    if (sample_rate <= 0.0f) return false;
    
    sample_rate_ = sample_rate;
    channels_ = channels;
    
    initialized_ = true;
    return true;
}

// Check if initialized
bool FreeDV::isInitialized() const {
    return initialized_;
}


// Set FreeDV mode
bool FreeDV::setMode(FreeDVMode mode) {
    if (!initialized_) return false;
    
    // Validate mode
    if (static_cast<int>(mode) < static_cast<int>(FreeDVMode::MODE_1600) || 
        static_cast<int>(mode) > static_cast<int>(FreeDVMode::MODE_2020C)) {
        return false;
    }
    
    current_mode_ = mode;
    return true;
}

// Get current mode
FreeDVMode FreeDV::getCurrentMode() const {
    return current_mode_;
}

// Process audio data
std::vector<float> FreeDV::process(const std::vector<float>& input) {
    if (!initialized_) return input;
    
    std::vector<float> output = input;
    return output;
}

// Encode audio
std::vector<uint8_t> FreeDV::encode(const std::vector<float>& input) {
    if (!initialized_) return std::vector<uint8_t>();
    
    // Simple encoding - just convert float to bytes
    std::vector<uint8_t> output(input.size() * sizeof(float));
    std::memcpy(output.data(), input.data(), input.size() * sizeof(float));
    
    // Apply encryption if enabled
    if (encryption_enabled_ && encryption_) {
        output = encryption_->encrypt(output);
    }
    
    return output;
}

// Decode audio
std::vector<float> FreeDV::decode(const std::vector<uint8_t>& input) {
    if (!initialized_) return std::vector<float>();
    
    std::vector<uint8_t> decrypted_data = input;
    
    // Apply decryption if encryption is enabled
    if (encryption_enabled_ && encryption_) {
        decrypted_data = encryption_->decrypt(input);
        if (decrypted_data.empty()) {
            return std::vector<float>(); // Decryption failed
        }
    }
    
    // Simple decoding - just convert bytes to float
    std::vector<float> output(decrypted_data.size() / sizeof(float));
    std::memcpy(output.data(), decrypted_data.data(), decrypted_data.size());
    return output;
}

// Set OFDM parameters
bool FreeDV::setOFDMParameters(uint32_t fft_size, uint32_t num_subcarriers, uint32_t guard_interval) {
    if (!initialized_) return false;
    fft_size_ = fft_size;
    num_subcarriers_ = num_subcarriers;
    guard_interval_ = guard_interval;
    return true;
}

// Set voice encoding parameters
bool FreeDV::setVoiceEncodingParameters(uint32_t bitrate, uint32_t frame_size) {
    if (!initialized_) return false;
    bitrate_ = bitrate;
    frame_size_ = frame_size;
    return true;
}

// Set error correction parameters
bool FreeDV::setErrorCorrection(bool enabled, float strength) {
    if (!initialized_) return false;
    (void)enabled; // Suppress unused parameter warning
    (void)strength; // Suppress unused parameter warning
    return true;
}

// Set synchronization parameters
bool FreeDV::setSynchronization(bool enabled, float threshold) {
    if (!initialized_) return false;
    (void)enabled; // Suppress unused parameter warning
    (void)threshold; // Suppress unused parameter warning
    return true;
}

// Set HF optimization parameters
bool FreeDV::setHFParameters(bool enabled, float strength) {
    if (!initialized_) return false;
    (void)enabled; // Suppress unused parameter warning
    (void)strength; // Suppress unused parameter warning
    return true;
}

// Check if processing is active
bool FreeDV::isProcessingActive() const {
    return initialized_;
}

// Get system status
std::string FreeDV::getStatus() const {
    std::ostringstream oss;
    oss << "FreeDV Status:\n";
    oss << "Initialized: " << (initialized_ ? "Yes" : "No") << "\n";
    oss << "Mode: " << static_cast<int>(current_mode_) << "\n";
    oss << "Sample Rate: " << sample_rate_ << " Hz\n";
    oss << "Bitrate: " << bitrate_ << " bps\n";
    return oss.str();
}

// Get mode information
std::string FreeDV::getModeInfo(FreeDVMode mode) const {
    (void)mode; // Suppress unused parameter warning
    return "FreeDV Mode Information";
}

// Get available modes
std::vector<FreeDVMode> FreeDV::getAvailableModes() const {
    return {FreeDVMode::MODE_1600, FreeDVMode::MODE_700, FreeDVMode::MODE_700D, 
            FreeDVMode::MODE_2020, FreeDVMode::MODE_2020B, FreeDVMode::MODE_2020C};
}

// Enable ChaCha20-Poly1305 encryption
bool FreeDV::enableEncryption(const std::vector<uint8_t>& key) {
    if (!initialized_) {
        encryption_enabled_ = false;
        return false;
    }
    
    // Check if key length matches current security level
    size_t expected_length = encryption_->getKeyLength();
    if (key.size() != expected_length) {
        encryption_enabled_ = false;
        return false;
    }
    
    encryption_key_ = key;
    encryption_enabled_ = encryption_->setKey(key);
    return encryption_enabled_;
}

// Enable encryption with key string
bool FreeDV::enableEncryptionFromString(const std::string& key_string) {
    if (!initialized_) {
        encryption_enabled_ = false;
        return false;
    }
    
    // Check if key string length matches current security level
    size_t expected_length = encryption_->getKeyLength() * 2; // 2 hex chars per byte
    if (key_string.length() != expected_length) {
        encryption_enabled_ = false;
        return false;
    }
    
    encryption_enabled_ = encryption_->setKeyFromString(key_string);
    if (encryption_enabled_) {
        encryption_key_ = encryption_->stringToKey(key_string);
    }
    return encryption_enabled_;
}

// Disable encryption
void FreeDV::disableEncryption() {
    encryption_enabled_ = false;
    std::fill(encryption_key_.begin(), encryption_key_.end(), 0);
}

// Check if encryption is enabled
bool FreeDV::isEncryptionEnabled() const {
    return encryption_enabled_;
}

// Generate random encryption key
std::vector<uint8_t> FreeDV::generateEncryptionKey() {
    return crypto::ChaCha20Poly1305::generateKey();
}

// Get encryption status
std::string FreeDV::getEncryptionStatus() const {
    std::ostringstream oss;
    oss << "FreeDV Encryption Status:\n";
    oss << "Encryption Enabled: " << (encryption_enabled_ ? "Yes" : "No") << "\n";
    if (encryption_enabled_) {
        oss << "Algorithm: ChaCha20-Poly1305\n";
        oss << "Key Length: 128 bits (16 bytes)\n";
        oss << "Security Level: 128-bit equivalent\n";
        oss << "Authentication: Poly1305 MAC\n";
        oss << "Encryption: ChaCha20 stream cipher\n";
    } else {
        oss << "Voice data transmitted in plaintext\n";
    }
    return oss.str();
}


} // namespace freedv
} // namespace fgcom
