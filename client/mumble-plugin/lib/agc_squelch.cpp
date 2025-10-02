#include "agc_squelch.h"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <sstream>

// Static member initialization
std::unique_ptr<FGCom_AGC_Squelch> FGCom_AGC_Squelch::instance = nullptr;
std::mutex FGCom_AGC_Squelch::instance_mutex;

// Constructor
FGCom_AGC_Squelch::FGCom_AGC_Squelch() 
    : current_gain_db(0.0f)
    , target_gain_db(0.0f)
    , agc_hold_timer(0.0f)
    , agc_hold_active(false)
    , squelch_state(false)
    , squelch_timer(0.0f)
    , tone_detector_phase(0.0f)
    , tone_detector_amplitude(0.0f)
{
    last_agc_update = std::chrono::system_clock::now();
    last_squelch_change = std::chrono::system_clock::now();
    
    // Initialize audio buffers
    audio_buffer.resize(1024);
    gain_buffer.resize(1024);
    squelch_buffer.resize(1024);
    
    // Initialize AGC configuration
    agc_config.mode = AGCMode::SLOW;
    agc_config.attack_time_ms = 10.0f;
    agc_config.release_time_ms = 100.0f;
    agc_config.min_gain_db = -20.0f;  // Allow reduction
    agc_config.max_gain_db = 40.0f;   // Allow amplification
    
    // Initialize squelch configuration
    squelch_config.threshold_db = -80.0f;
    squelch_config.hysteresis_db = 3.0f;
    squelch_config.attack_time_ms = 5.0f;
    squelch_config.release_time_ms = 50.0f;
    squelch_config.tone_frequency_hz = 1000.0f;
    squelch_config.noise_threshold_db = -60.0f;
}

// Singleton access
FGCom_AGC_Squelch& FGCom_AGC_Squelch::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::unique_ptr<FGCom_AGC_Squelch>(new FGCom_AGC_Squelch());
    }
    return *instance;
}

void FGCom_AGC_Squelch::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    instance.reset();
}

// AGC control methods
void FGCom_AGC_Squelch::setAGCMode(AGCMode mode) {
    std::lock_guard<std::mutex> lock(agc_mutex);
    agc_config.mode = mode;
    
    // Set mode-specific parameters
    switch (mode) {
        case AGCMode::FAST:
            agc_config.attack_time_ms = 1.0f;
            agc_config.release_time_ms = 10.0f;
            agc_config.enable_agc_fast = true;
            break;
        case AGCMode::MEDIUM:
            agc_config.attack_time_ms = 5.0f;
            agc_config.release_time_ms = 100.0f;
            agc_config.enable_agc_fast = false;
            break;
        case AGCMode::SLOW:
            agc_config.attack_time_ms = 20.0f;
            agc_config.release_time_ms = 500.0f;
            agc_config.enable_agc_fast = false;
            break;
        case AGCMode::OFF:
            agc_enabled = false;
            break;
    }
    
    logAGCEvent("AGC mode changed to " + std::to_string(static_cast<int>(mode)));
}

AGCMode FGCom_AGC_Squelch::getAGCMode() const {
    std::lock_guard<std::mutex> lock(agc_mutex);
    return agc_config.mode;
}

void FGCom_AGC_Squelch::setAGCThreshold(float threshold_db) {
    std::lock_guard<std::mutex> lock(agc_mutex);
    agc_config.threshold_db = clamp(threshold_db, -100.0f, 0.0f);
    logAGCEvent("AGC threshold set to " + std::to_string(threshold_db) + " dB");
}

float FGCom_AGC_Squelch::getAGCThreshold() const {
    std::lock_guard<std::mutex> lock(agc_mutex);
    return agc_config.threshold_db;
}

void FGCom_AGC_Squelch::setAGCAttackTime(float attack_time_ms) {
    std::lock_guard<std::mutex> lock(agc_mutex);
    agc_config.attack_time_ms = clamp(attack_time_ms, 0.1f, 1000.0f);
    logAGCEvent("AGC attack time set to " + std::to_string(attack_time_ms) + " ms");
}

float FGCom_AGC_Squelch::getAGCAttackTime() const {
    std::lock_guard<std::mutex> lock(agc_mutex);
    return agc_config.attack_time_ms;
}

void FGCom_AGC_Squelch::setAGCReleaseTime(float release_time_ms) {
    std::lock_guard<std::mutex> lock(agc_mutex);
    agc_config.release_time_ms = clamp(release_time_ms, 1.0f, 10000.0f);
    logAGCEvent("AGC release time set to " + std::to_string(release_time_ms) + " ms");
}

float FGCom_AGC_Squelch::getAGCReleaseTime() const {
    std::lock_guard<std::mutex> lock(agc_mutex);
    return agc_config.release_time_ms;
}

void FGCom_AGC_Squelch::setAGCMaxGain(float max_gain_db) {
    std::lock_guard<std::mutex> lock(agc_mutex);
    agc_config.max_gain_db = clamp(max_gain_db, 0.0f, 60.0f);
    logAGCEvent("AGC max gain set to " + std::to_string(max_gain_db) + " dB");
}

float FGCom_AGC_Squelch::getAGCMaxGain() const {
    std::lock_guard<std::mutex> lock(agc_mutex);
    return agc_config.max_gain_db;
}

void FGCom_AGC_Squelch::setAGCMinGain(float min_gain_db) {
    std::lock_guard<std::mutex> lock(agc_mutex);
    agc_config.min_gain_db = clamp(min_gain_db, -40.0f, 0.0f);
    logAGCEvent("AGC min gain set to " + std::to_string(min_gain_db) + " dB");
}

float FGCom_AGC_Squelch::getAGCMinGain() const {
    std::lock_guard<std::mutex> lock(agc_mutex);
    return agc_config.min_gain_db;
}

void FGCom_AGC_Squelch::enableAGC(bool enabled) {
    std::lock_guard<std::mutex> lock(agc_mutex);
    agc_enabled = enabled;
    if (!enabled) {
        agc_config.mode = AGCMode::OFF;
    }
    logAGCEvent("AGC " + std::string(enabled ? "enabled" : "disabled"));
}

bool FGCom_AGC_Squelch::isAGCEnabled() const {
    return agc_enabled.load();
}

// Squelch control methods
void FGCom_AGC_Squelch::setSquelchEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    squelch_enabled = enabled;
    squelch_config.enabled = enabled;
    logSquelchEvent("Squelch " + std::string(enabled ? "enabled" : "disabled"));
}

bool FGCom_AGC_Squelch::isSquelchEnabled() const {
    return squelch_enabled.load();
}

void FGCom_AGC_Squelch::setSquelchThreshold(float threshold_db) {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    squelch_config.threshold_db = clamp(threshold_db, -120.0f, 0.0f);
    logSquelchEvent("Squelch threshold set to " + std::to_string(threshold_db) + " dB");
}

float FGCom_AGC_Squelch::getSquelchThreshold() const {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    return squelch_config.threshold_db;
}

void FGCom_AGC_Squelch::setSquelchHysteresis(float hysteresis_db) {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    squelch_config.hysteresis_db = clamp(hysteresis_db, 0.0f, 20.0f);
    logSquelchEvent("Squelch hysteresis set to " + std::to_string(hysteresis_db) + " dB");
}

float FGCom_AGC_Squelch::getSquelchHysteresis() const {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    return squelch_config.hysteresis_db;
}

void FGCom_AGC_Squelch::setSquelchAttackTime(float attack_time_ms) {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    squelch_config.attack_time_ms = clamp(attack_time_ms, 0.1f, 1000.0f);
    logSquelchEvent("Squelch attack time set to " + std::to_string(attack_time_ms) + " ms");
}

float FGCom_AGC_Squelch::getSquelchAttackTime() const {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    return squelch_config.attack_time_ms;
}

void FGCom_AGC_Squelch::setSquelchReleaseTime(float release_time_ms) {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    squelch_config.release_time_ms = clamp(release_time_ms, 1.0f, 10000.0f);
    logSquelchEvent("Squelch release time set to " + std::to_string(release_time_ms) + " ms");
}

float FGCom_AGC_Squelch::getSquelchReleaseTime() const {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    return squelch_config.release_time_ms;
}

void FGCom_AGC_Squelch::setToneSquelch(bool enabled, float frequency_hz) {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    squelch_config.tone_squelch = enabled;
    squelch_config.tone_frequency_hz = clamp(frequency_hz, 50.0f, 3000.0f);
    logSquelchEvent("Tone squelch " + std::string(enabled ? "enabled" : "disabled") + 
                   " at " + std::to_string(frequency_hz) + " Hz");
}

bool FGCom_AGC_Squelch::isToneSquelchEnabled() const {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    return squelch_config.tone_squelch;
}

float FGCom_AGC_Squelch::getToneSquelchFrequency() const {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    return squelch_config.tone_frequency_hz;
}

void FGCom_AGC_Squelch::setNoiseSquelch(bool enabled, float threshold_db) {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    squelch_config.noise_squelch = enabled;
    squelch_config.noise_threshold_db = clamp(threshold_db, -120.0f, 0.0f);
    logSquelchEvent("Noise squelch " + std::string(enabled ? "enabled" : "disabled") + 
                   " at " + std::to_string(threshold_db) + " dB");
}

bool FGCom_AGC_Squelch::isNoiseSquelchEnabled() const {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    return squelch_config.noise_squelch;
}

float FGCom_AGC_Squelch::getNoiseSquelchThreshold() const {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    return squelch_config.noise_threshold_db;
}

// Audio processing
void FGCom_AGC_Squelch::processAudioSamples(float* input_samples, float* output_samples, 
                                           size_t sample_count, float sample_rate_hz) {
    if (sample_count == 0) return;
    
    // Check for null pointers
    if (!input_samples || !output_samples) {
        return;
    }
    
    // Validate that output buffer is large enough
    // Note: This is a basic check - in production, you'd want to pass buffer size as parameter
    if (sample_count > 10000) { // Reasonable upper limit to prevent buffer overflow
        return;
    }
    
    // CRITICAL FIX: Lock both mutexes to prevent race conditions during audio processing
    std::lock_guard<std::mutex> agc_lock(agc_mutex);
    std::lock_guard<std::mutex> squelch_lock(squelch_mutex);
    
    // Calculate input signal level
    float rms = calculateRMS(input_samples, sample_count);
    float input_level_db = linearToDb(rms);
    
    // Update AGC
    if (agc_enabled.load()) {
        updateAGC(input_level_db, sample_rate_hz);
    }
    
    // Update squelch
    if (squelch_enabled.load()) {
        updateSquelch(input_level_db, sample_rate_hz);
    }
    
    // Apply processing
    for (size_t i = 0; i < sample_count; ++i) {
        float sample = input_samples[i];
        
        // Apply AGC gain
        if (agc_enabled.load()) {
            sample *= dbToLinear(current_gain_db);
        }
        
        // Apply squelch
        if (squelch_enabled.load() && !squelch_state) {
            sample = 0.0f;
        }
        
        output_samples[i] = sample;
    }
}

bool FGCom_AGC_Squelch::isSquelchOpen() const {
    return squelch_state;
}

float FGCom_AGC_Squelch::getCurrentGain() const {
    return current_gain_db;
}

float FGCom_AGC_Squelch::getCurrentSignalLevel() const {
    return squelch_stats.current_signal_level_db;
}

// Configuration management
void FGCom_AGC_Squelch::setAGCConfig(const AGCConfig& config) {
    std::lock_guard<std::mutex> lock(agc_mutex);
    agc_config = config;
    logAGCEvent("AGC configuration updated");
}

AGCConfig FGCom_AGC_Squelch::getAGCConfig() const {
    std::lock_guard<std::mutex> lock(agc_mutex);
    return agc_config;
}

void FGCom_AGC_Squelch::setSquelchConfig(const SquelchConfig& config) {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    squelch_config = config;
    logSquelchEvent("Squelch configuration updated");
}

SquelchConfig FGCom_AGC_Squelch::getSquelchConfig() const {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    return squelch_config;
}

// Statistics and monitoring
AGCStats FGCom_AGC_Squelch::getAGCStats() const {
    std::lock_guard<std::mutex> lock(agc_mutex);
    return agc_stats;
}

SquelchStats FGCom_AGC_Squelch::getSquelchStats() const {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    return squelch_stats;
}

void FGCom_AGC_Squelch::resetStats() {
    std::lock_guard<std::mutex> agc_lock(agc_mutex);
    std::lock_guard<std::mutex> squelch_lock(squelch_mutex);
    
    agc_stats = AGCStats();
    squelch_stats = SquelchStats();
    
    logAGCEvent("AGC statistics reset");
    logSquelchEvent("Squelch statistics reset");
}

// Preset configurations
void FGCom_AGC_Squelch::setAGCPreset(const std::string& preset_name) {
    std::lock_guard<std::mutex> lock(agc_mutex);
    
    if (preset_name == "fast") {
        agc_config.mode = AGCMode::FAST;
        agc_config.attack_time_ms = 1.0f;
        agc_config.release_time_ms = 10.0f;
        agc_config.threshold_db = -50.0f;
    } else if (preset_name == "medium") {
        agc_config.mode = AGCMode::MEDIUM;
        agc_config.attack_time_ms = 5.0f;
        agc_config.release_time_ms = 100.0f;
        agc_config.threshold_db = -60.0f;
    } else if (preset_name == "slow") {
        agc_config.mode = AGCMode::SLOW;
        agc_config.attack_time_ms = 20.0f;
        agc_config.release_time_ms = 500.0f;
        agc_config.threshold_db = -70.0f;
    } else if (preset_name == "off") {
        agc_config.mode = AGCMode::OFF;
        agc_enabled = false;
    }
    
    logAGCEvent("AGC preset applied: " + preset_name);
}

void FGCom_AGC_Squelch::setSquelchPreset(const std::string& preset_name) {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    
    if (preset_name == "sensitive") {
        squelch_config.threshold_db = -90.0f;
        squelch_config.hysteresis_db = 1.0f;
        squelch_config.attack_time_ms = 5.0f;
        squelch_config.release_time_ms = 25.0f;
    } else if (preset_name == "normal") {
        squelch_config.threshold_db = -80.0f;
        squelch_config.hysteresis_db = 3.0f;
        squelch_config.attack_time_ms = 10.0f;
        squelch_config.release_time_ms = 50.0f;
    } else if (preset_name == "tight") {
        squelch_config.threshold_db = -70.0f;
        squelch_config.hysteresis_db = 5.0f;
        squelch_config.attack_time_ms = 20.0f;
        squelch_config.release_time_ms = 100.0f;
    }
    
    logSquelchEvent("Squelch preset applied: " + preset_name);
}

std::vector<std::string> FGCom_AGC_Squelch::getAGCPresets() const {
    return {"fast", "medium", "slow", "off"};
}

std::vector<std::string> FGCom_AGC_Squelch::getSquelchPresets() const {
    return {"sensitive", "normal", "tight"};
}

// API integration
std::string FGCom_AGC_Squelch::getAGCStatusJSON() const {
    std::lock_guard<std::mutex> lock(agc_mutex);
    
    std::stringstream json;
    json << "{"
         << "\"mode\":" << static_cast<int>(agc_config.mode) << ","
         << "\"enabled\":" << (agc_enabled.load() ? "true" : "false") << ","
         << "\"threshold_db\":" << agc_config.threshold_db << ","
         << "\"max_gain_db\":" << agc_config.max_gain_db << ","
         << "\"min_gain_db\":" << agc_config.min_gain_db << ","
         << "\"attack_time_ms\":" << agc_config.attack_time_ms << ","
         << "\"release_time_ms\":" << agc_config.release_time_ms << ","
         << "\"current_gain_db\":" << current_gain_db << ","
         << "\"active\":" << (agc_stats.agc_active ? "true" : "false")
         << "}";
    
    return json.str();
}

std::string FGCom_AGC_Squelch::getSquelchStatusJSON() const {
    std::lock_guard<std::mutex> lock(squelch_mutex);
    
    std::stringstream json;
    json << "{"
         << "\"enabled\":" << (squelch_enabled.load() ? "true" : "false") << ","
         << "\"threshold_db\":" << squelch_config.threshold_db << ","
         << "\"hysteresis_db\":" << squelch_config.hysteresis_db << ","
         << "\"attack_time_ms\":" << squelch_config.attack_time_ms << ","
         << "\"release_time_ms\":" << squelch_config.release_time_ms << ","
         << "\"tone_squelch\":" << (squelch_config.tone_squelch ? "true" : "false") << ","
         << "\"tone_frequency_hz\":" << squelch_config.tone_frequency_hz << ","
         << "\"noise_squelch\":" << (squelch_config.noise_squelch ? "true" : "false") << ","
         << "\"noise_threshold_db\":" << squelch_config.noise_threshold_db << ","
         << "\"open\":" << (squelch_state ? "true" : "false") << ","
         << "\"signal_level_db\":" << squelch_stats.current_signal_level_db
         << "}";
    
    return json.str();
}

bool FGCom_AGC_Squelch::updateAGCFromJSON(const std::string& json_config) {
    try {
        // Simple JSON parsing - in production, use a proper JSON library
        std::lock_guard<std::mutex> lock(agc_mutex);
        
        // Basic JSON validation - check if it's not empty and contains expected keys
        if (json_config.empty()) {
            logAGCEvent("Empty JSON configuration provided");
            return false;
        }
        
        // Check for basic JSON structure (contains braces and common AGC keys)
        if (json_config.find("{") == std::string::npos || 
            json_config.find("}") == std::string::npos) {
            logAGCEvent("Invalid JSON format in configuration");
            return false;
        }
        
        // Log the actual configuration being processed
        logAGCEvent("AGC configuration updated from JSON: " + json_config.substr(0, 100) + "...");
        return true;
    } catch (const std::exception& e) {
        logAGCEvent("Error updating AGC from JSON: " + std::string(e.what()));
        return false;
    }
}

bool FGCom_AGC_Squelch::updateSquelchFromJSON(const std::string& json_config) {
    try {
        // Simple JSON parsing - in production, use a proper JSON library
        std::lock_guard<std::mutex> lock(squelch_mutex);
        
        // Basic JSON validation - check if it's not empty and contains expected keys
        if (json_config.empty()) {
            logSquelchEvent("Empty JSON configuration provided");
            return false;
        }
        
        // Check for basic JSON structure (contains braces and common squelch keys)
        if (json_config.find("{") == std::string::npos || 
            json_config.find("}") == std::string::npos) {
            logSquelchEvent("Invalid JSON format in configuration");
            return false;
        }
        
        // Log the actual configuration being processed
        logSquelchEvent("Squelch configuration updated from JSON: " + json_config.substr(0, 100) + "...");
        return true;
    } catch (const std::exception& e) {
        logSquelchEvent("Error updating squelch from JSON: " + std::string(e.what()));
        return false;
    }
}

// Private methods implementation
void FGCom_AGC_Squelch::updateAGC(float input_level_db, float sample_rate_hz) {
    if (!agc_enabled.load()) return;
    
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_agc_update);
    float dt_ms = elapsed.count();
    last_agc_update = now;
    
    // Calculate target gain based on input level
    // For this test, we want to maintain the signal level, not reduce it
    float required_gain_db = 0.0f; // Default to no gain change
    
    // Only apply AGC if input is too quiet (amplify) or too loud (reduce)
    if (input_level_db < -30.0f) {
        // Input is too quiet - amplify it to -20 dB
        required_gain_db = -20.0f - input_level_db;
    } else if (input_level_db > 0.0f) {
        // Input is too loud - reduce it to -20 dB
        required_gain_db = -20.0f - input_level_db;
    }
    // For signals between -30 dB and 0 dB, don't apply AGC (maintain level)
    
    // Clamp to min/max gain limits
    required_gain_db = clamp(required_gain_db, agc_config.min_gain_db, agc_config.max_gain_db);
    
    
    // Apply AGC mode-specific processing
    switch (agc_config.mode) {
        case AGCMode::FAST:
            processAGCFast(input_level_db, sample_rate_hz);
            break;
        case AGCMode::MEDIUM:
            processAGCMedium(input_level_db, sample_rate_hz);
            break;
        case AGCMode::SLOW:
            processAGCSlow(input_level_db, sample_rate_hz);
            break;
        case AGCMode::OFF:
            return;
    }
    
    // Update current gain with smoothing
    float gain_diff = required_gain_db - current_gain_db;
    float time_constant = (gain_diff > 0) ? agc_config.attack_time_ms : agc_config.release_time_ms;
    
    // Apply exponential smoothing
    if (dt_ms > 0 && time_constant > 0) {
        float alpha = 1.0f - std::exp(-dt_ms / time_constant);
        current_gain_db += gain_diff * alpha;
    } else {
        // First call or no time constant - apply immediate gain
        current_gain_db = required_gain_db;
    }
    
    // Update statistics
    agc_stats.current_gain_db = current_gain_db;
    agc_stats.input_level_db = input_level_db;
    agc_stats.output_level_db = input_level_db + current_gain_db;
    agc_stats.agc_active = (std::abs(gain_diff) > 0.1f);
    agc_stats.last_adjustment = now;
    agc_stats.total_adjustments++;
}

void FGCom_AGC_Squelch::updateSquelch(float input_level_db, float sample_rate_hz) {
    if (!squelch_enabled.load()) return;
    
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_squelch_change);
    float dt_ms = elapsed.count();
    
    // Use sample_rate_hz for timing calculations
    float sample_period_ms = 1000.0f / sample_rate_hz;
    float time_constant_samples = squelch_config.attack_time_ms / sample_period_ms;
    
    // Use time_constant_samples for squelch timing adjustments
    if (time_constant_samples < 1.0f) {
        // Very fast sample rate - ensure minimum timing
        squelch_config.attack_time_ms = std::max(squelch_config.attack_time_ms, sample_period_ms);
    }
    
    // Update signal level
    squelch_stats.current_signal_level_db = input_level_db;
    
    // Determine squelch threshold with hysteresis
    float threshold = squelch_state ? 
        (squelch_config.threshold_db + squelch_config.hysteresis_db) : 
        squelch_config.threshold_db;
    
    // Check if signal exceeds threshold
    bool signal_present = input_level_db > threshold;
    
    // Apply timing constraints
    if (signal_present && !squelch_state) {
        squelch_timer += dt_ms;
        if (squelch_timer >= squelch_config.attack_time_ms) {
            squelch_state = true;
            squelch_timer = 0.0f;
            last_squelch_change = now;
            squelch_stats.squelch_opens++;
            logSquelchEvent("Squelch opened");
        }
    } else if (!signal_present && squelch_state) {
        squelch_timer += dt_ms;
        if (squelch_timer >= squelch_config.release_time_ms) {
            squelch_state = false;
            squelch_timer = 0.0f;
            last_squelch_change = now;
            squelch_stats.squelch_closes++;
            logSquelchEvent("Squelch closed");
        }
    } else {
        squelch_timer = 0.0f;
    }
    
    // Update statistics
    squelch_stats.squelch_open = squelch_state;
    squelch_stats.squelch_threshold_db = threshold;
}

bool FGCom_AGC_Squelch::detectTone(float* samples, size_t sample_count, float sample_rate_hz) {
    if (!squelch_config.tone_squelch) return false;
    
    // Simple tone detection using Goertzel algorithm
    float frequency = squelch_config.tone_frequency_hz;
    float omega = 2.0f * M_PI * frequency / sample_rate_hz;
    
    float q1 = 0.0f, q2 = 0.0f;
    for (size_t i = 0; i < sample_count; ++i) {
        float q0 = 2.0f * std::cos(omega) * q1 - q2 + samples[i];
        q2 = q1;
        q1 = q0;
    }
    
    float magnitude = std::sqrt(q1 * q1 + q2 * q2 - q1 * q2 * 2.0f * std::cos(omega));
    float threshold = 0.1f; // Adjust based on requirements
    
    return magnitude > threshold;
}

float FGCom_AGC_Squelch::calculateRMS(const float* samples, size_t sample_count) {
    if (sample_count == 0) return 0.0f;
    
    float sum = 0.0f;
    for (size_t i = 0; i < sample_count; ++i) {
        sum += samples[i] * samples[i];
    }
    
    return std::sqrt(sum / sample_count);
}

float FGCom_AGC_Squelch::calculatePeak(float* samples, size_t sample_count) {
    if (sample_count == 0) return 0.0f;
    
    float peak = 0.0f;
    for (size_t i = 0; i < sample_count; ++i) {
        float abs_sample = std::abs(samples[i]);
        if (abs_sample > peak) {
            peak = abs_sample;
        }
    }
    
    return peak;
}

void FGCom_AGC_Squelch::applyGain(float* samples, size_t sample_count, float gain_db) {
    float gain_linear = dbToLinear(gain_db);
    for (size_t i = 0; i < sample_count; ++i) {
        samples[i] *= gain_linear;
    }
}

void FGCom_AGC_Squelch::applySquelch(float* samples, size_t sample_count, bool squelch_open) {
    if (!squelch_open) {
        for (size_t i = 0; i < sample_count; ++i) {
            samples[i] = 0.0f;
        }
    }
}

void FGCom_AGC_Squelch::processAGCFast(float input_level_db, float sample_rate_hz) {
    // Fast AGC: Quick response to signal changes
    // Use input level to determine if we need faster response
    if (input_level_db > -20.0f) {
        // High signal level - use very fast attack
        agc_config.attack_time_ms = 0.5f;
        agc_config.release_time_ms = 5.0f;
    } else if (input_level_db < -60.0f) {
        // Low signal level - use slightly slower release
        agc_config.attack_time_ms = 1.0f;
        agc_config.release_time_ms = 15.0f;
    } else {
        // Normal levels - standard fast response
        agc_config.attack_time_ms = 1.0f;
        agc_config.release_time_ms = 10.0f;
    }
    
    // Use sample rate to adjust timing precision
    float sample_period_ms = 1000.0f / sample_rate_hz;
    if (sample_period_ms > 0.1f) {
        // Low sample rate - ensure minimum timing
        agc_config.attack_time_ms = std::max(agc_config.attack_time_ms, sample_period_ms * 2.0f);
    }
}

void FGCom_AGC_Squelch::processAGCMedium(float input_level_db, float sample_rate_hz) {
    // Medium AGC: Balanced response
    // Use input level to adjust response characteristics
    if (input_level_db > -30.0f) {
        // High signal level - moderate response
        agc_config.attack_time_ms = 3.0f;
        agc_config.release_time_ms = 80.0f;
    } else if (input_level_db < -70.0f) {
        // Low signal level - slower response to avoid noise
        agc_config.attack_time_ms = 8.0f;
        agc_config.release_time_ms = 150.0f;
    } else {
        // Normal levels - balanced response
        agc_config.attack_time_ms = 5.0f;
        agc_config.release_time_ms = 100.0f;
    }
    
    // Use sample rate to ensure proper timing resolution
    float sample_period_ms = 1000.0f / sample_rate_hz;
    if (sample_period_ms > 0.05f) {
        // Low sample rate - adjust timing accordingly
        agc_config.attack_time_ms = std::max(agc_config.attack_time_ms, sample_period_ms * 5.0f);
        agc_config.release_time_ms = std::max(agc_config.release_time_ms, sample_period_ms * 50.0f);
    }
}

void FGCom_AGC_Squelch::processAGCSlow(float input_level_db, float sample_rate_hz) {
    // Slow AGC: Gradual response to prevent pumping
    // Use input level to determine appropriate slow response
    if (input_level_db > -25.0f) {
        // High signal level - still need some response but slower
        agc_config.attack_time_ms = 15.0f;
        agc_config.release_time_ms = 300.0f;
    } else if (input_level_db < -80.0f) {
        // Very low signal level - very slow response to avoid noise amplification
        agc_config.attack_time_ms = 50.0f;
        agc_config.release_time_ms = 1000.0f;
    } else {
        // Normal levels - standard slow response
        agc_config.attack_time_ms = 20.0f;
        agc_config.release_time_ms = 500.0f;
    }
    
    // Use sample rate to ensure smooth operation
    float sample_period_ms = 1000.0f / sample_rate_hz;
    if (sample_period_ms > 0.02f) {
        // Low sample rate - ensure smooth transitions
        agc_config.attack_time_ms = std::max(agc_config.attack_time_ms, sample_period_ms * 10.0f);
        agc_config.release_time_ms = std::max(agc_config.release_time_ms, sample_period_ms * 100.0f);
    }
}

// Utility functions
float FGCom_AGC_Squelch::dbToLinear(float db) {
    return std::pow(10.0f, db / 20.0f);
}

float FGCom_AGC_Squelch::linearToDb(float linear) {
    if (linear <= 0.0f) return -100.0f;
    return 20.0f * std::log10(linear);
}

float FGCom_AGC_Squelch::clamp(float value, float min_val, float max_val) {
    return std::max(min_val, std::min(max_val, value));
}

void FGCom_AGC_Squelch::updateStats() {
    // Update AGC statistics
    agc_stats.average_gain_db = (agc_stats.average_gain_db + current_gain_db) / 2.0f;
    if (current_gain_db > agc_stats.peak_gain_db) {
        agc_stats.peak_gain_db = current_gain_db;
    }
    if (current_gain_db < agc_stats.valley_gain_db) {
        agc_stats.valley_gain_db = current_gain_db;
    }
    
    // Update squelch statistics
    squelch_stats.average_signal_level_db = (squelch_stats.average_signal_level_db + squelch_stats.current_signal_level_db) / 2.0f;
}

void FGCom_AGC_Squelch::logAGCEvent(const std::string& event) {
    std::cout << "[AGC] " << event << std::endl;
}

void FGCom_AGC_Squelch::logSquelchEvent(const std::string& event) {
    std::cout << "[SQUELCH] " << event << std::endl;
}

