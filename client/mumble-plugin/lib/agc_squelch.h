#ifndef FGCOM_AGC_SQUELCH_H
#define FGCOM_AGC_SQUELCH_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>

// AGC (Automatic Gain Control) modes
enum class AGCMode {
    OFF = 0,
    FAST = 1,
    MEDIUM = 2,
    SLOW = 3
};

// AGC configuration structure
struct AGCConfig {
    AGCMode mode = AGCMode::SLOW;
    float threshold_db = -60.0f;        // AGC threshold in dB
    float max_gain_db = 40.0f;          // Maximum gain in dB
    float min_gain_db = -20.0f;         // Minimum gain in dB
    float attack_time_ms = 5.0f;        // Attack time in milliseconds
    float release_time_ms = 100.0f;     // Release time in milliseconds
    bool enable_agc_hold = true;        // Enable AGC hold function
    float hold_time_ms = 1000.0f;       // AGC hold time in milliseconds
    bool enable_agc_fast = false;       // Enable fast AGC response
    float fast_threshold_db = -40.0f;   // Fast AGC threshold
    float fast_attack_time_ms = 1.0f;   // Fast AGC attack time
    float fast_release_time_ms = 10.0f; // Fast AGC release time
};

// Squelch configuration structure
struct SquelchConfig {
    bool enabled = true;                // Squelch enabled/disabled
    float threshold_db = -80.0f;        // Squelch threshold in dB
    float hysteresis_db = 3.0f;         // Hysteresis to prevent chattering
    float attack_time_ms = 10.0f;      // Squelch attack time
    float release_time_ms = 50.0f;      // Squelch release time
    bool tone_squelch = false;          // Enable tone squelch
    float tone_frequency_hz = 100.0f;   // Tone frequency for tone squelch
    float tone_tolerance_hz = 5.0f;     // Tone frequency tolerance
    bool noise_squelch = true;          // Enable noise squelch
    float noise_threshold_db = -70.0f;  // Noise squelch threshold
};

// AGC statistics and monitoring
struct AGCStats {
    float current_gain_db;
    float input_level_db;
    float output_level_db;
    float signal_to_noise_db;
    bool agc_active;
    std::chrono::system_clock::time_point last_adjustment;
    int total_adjustments;
    float average_gain_db;
    float peak_gain_db;
    float valley_gain_db;
};

// Squelch statistics and monitoring
struct SquelchStats {
    bool squelch_open;
    float current_signal_level_db;
    float squelch_threshold_db;
    std::chrono::system_clock::time_point last_squelch_change;
    int squelch_opens;
    int squelch_closes;
    float average_signal_level_db;
    bool tone_detected;
    float tone_strength_db;
};

// Main AGC and Squelch control class
class FGCom_AGC_Squelch {
private:
    static std::unique_ptr<FGCom_AGC_Squelch> instance;
    static std::mutex instance_mutex;
    
    AGCConfig agc_config;
    SquelchConfig squelch_config;
    AGCStats agc_stats;
    SquelchStats squelch_stats;
    
    // Internal state
    mutable std::mutex agc_mutex;
    mutable std::mutex squelch_mutex;
    std::atomic<bool> agc_enabled{true};
    std::atomic<bool> squelch_enabled{true};
    
    // AGC internal variables
    float current_gain_db;
    float target_gain_db;
    std::chrono::system_clock::time_point last_agc_update;
    float agc_hold_timer;
    bool agc_hold_active;
    
    // Squelch internal variables
    bool squelch_state;
    float squelch_timer;
    float tone_detector_phase;
    float tone_detector_amplitude;
    std::chrono::system_clock::time_point last_squelch_change;
    
    // Audio processing buffers
    std::vector<float> audio_buffer;
    std::vector<float> gain_buffer;
    std::vector<float> squelch_buffer;
    
    // Private constructor for singleton
    FGCom_AGC_Squelch();
    
public:
    // Singleton access
    static FGCom_AGC_Squelch& getInstance();
    static void destroyInstance();
    
    // AGC control methods
    void setAGCMode(AGCMode mode);
    AGCMode getAGCMode() const;
    void setAGCThreshold(float threshold_db);
    float getAGCThreshold() const;
    void setAGCAttackTime(float attack_time_ms);
    float getAGCAttackTime() const;
    void setAGCReleaseTime(float release_time_ms);
    float getAGCReleaseTime() const;
    void setAGCMaxGain(float max_gain_db);
    float getAGCMaxGain() const;
    void setAGCMinGain(float min_gain_db);
    float getAGCMinGain() const;
    void enableAGC(bool enabled);
    bool isAGCEnabled() const;
    
    // Squelch control methods
    void setSquelchEnabled(bool enabled);
    bool isSquelchEnabled() const;
    void setSquelchThreshold(float threshold_db);
    float getSquelchThreshold() const;
    void setSquelchHysteresis(float hysteresis_db);
    float getSquelchHysteresis() const;
    void setSquelchAttackTime(float attack_time_ms);
    float getSquelchAttackTime() const;
    void setSquelchReleaseTime(float release_time_ms);
    float getSquelchReleaseTime() const;
    void setToneSquelch(bool enabled, float frequency_hz = 100.0f);
    bool isToneSquelchEnabled() const;
    float getToneSquelchFrequency() const;
    void setNoiseSquelch(bool enabled, float threshold_db = -70.0f);
    bool isNoiseSquelchEnabled() const;
    float getNoiseSquelchThreshold() const;
    
    // Audio processing
    void processAudioSamples(float* input_samples, float* output_samples, 
                           size_t sample_count, float sample_rate_hz);
    bool isSquelchOpen() const;
    float getCurrentGain() const;
    float getCurrentSignalLevel() const;
    
    // Configuration management
    void setAGCConfig(const AGCConfig& config);
    AGCConfig getAGCConfig() const;
    void setSquelchConfig(const SquelchConfig& config);
    SquelchConfig getSquelchConfig() const;
    
    // Statistics and monitoring
    AGCStats getAGCStats() const;
    SquelchStats getSquelchStats() const;
    void resetStats();
    
    // Preset configurations
    void setAGCPreset(const std::string& preset_name);
    void setSquelchPreset(const std::string& preset_name);
    std::vector<std::string> getAGCPresets() const;
    std::vector<std::string> getSquelchPresets() const;
    
    // API integration
    std::string getAGCStatusJSON() const;
    std::string getSquelchStatusJSON() const;
    bool updateAGCFromJSON(const std::string& json_config);
    bool updateSquelchFromJSON(const std::string& json_config);
    
private:
    // Internal processing methods
    void updateAGC(float input_level_db, float sample_rate_hz);
    void updateSquelch(float input_level_db, float sample_rate_hz);
    bool detectTone(float* samples, size_t sample_count, float sample_rate_hz);
    float calculateRMS(float* samples, size_t sample_count);
    float calculatePeak(float* samples, size_t sample_count);
    void applyGain(float* samples, size_t sample_count, float gain_db);
    void applySquelch(float* samples, size_t sample_count, bool squelch_open);
    
    // AGC mode-specific processing
    void processAGCFast(float input_level_db, float sample_rate_hz);
    void processAGCMedium(float input_level_db, float sample_rate_hz);
    void processAGCSlow(float input_level_db, float sample_rate_hz);
    
    // Utility functions
    float dbToLinear(float db);
    float linearToDb(float linear);
    float clamp(float value, float min_val, float max_val);
    void updateStats();
    void logAGCEvent(const std::string& event);
    void logSquelchEvent(const std::string& event);
};

// Utility functions for AGC and Squelch
namespace AGC_Squelch_Utils {
    // AGC timing calculations
    float calculateAttackTime(AGCMode mode);
    float calculateReleaseTime(AGCMode mode);
    
    // Squelch calculations
    float calculateSquelchThreshold(float noise_floor_db, float desired_snr_db);
    float calculateHysteresis(float threshold_db, float signal_variance_db);
    
    // Audio level calculations
    float calculateAudioLevel(float* samples, size_t sample_count);
    float calculateSNR(float signal_level_db, float noise_level_db);
    
    // Preset configurations
    AGCConfig getAGCPreset(const std::string& preset_name);
    SquelchConfig getSquelchPreset(const std::string& preset_name);
    
    // JSON serialization
    std::string AGCConfigToJSON(const AGCConfig& config);
    std::string SquelchConfigToJSON(const SquelchConfig& config);
    AGCConfig JSONToAGCConfig(const std::string& json);
    SquelchConfig JSONToSquelchConfig(const std::string& json);
}

#endif // FGCOM_AGC_SQUELCH_H
