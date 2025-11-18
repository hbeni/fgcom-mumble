#ifndef FGCOM_CTCSS_SYSTEM_H
#define FGCOM_CTCSS_SYSTEM_H

#include <string>
#include <vector>
#include <map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <memory>

// CTCSS (Continuous Tone-Coded Squelch System) implementation
// Based on NATO military standards and international radio regulations

namespace CTCSS {

// CTCSS tone structure
struct CTCSSTone {
    float frequency_hz;           // Tone frequency in Hz
    std::string motorola_pl_code; // Motorola PL code (e.g., "1A", "2B")
    std::string description;      // Human-readable description
    bool is_nato_standard;        // NATO military standard tone
    bool is_restricted_region;    // Restricted in certain regions
    std::vector<std::string> restricted_regions; // List of restricted regions
};

// CTCSS configuration for a radio
struct CTCSSConfig {
    bool ctcss_enabled = false;
    float tx_tone_hz = 0.0f;      // Transmit tone (0.0 = no tone)
    float rx_tone_hz = 0.0f;      // Receive tone (0.0 = no tone)
    bool tone_decode_enabled = true;
    bool tone_encode_enabled = true;
    float tone_tolerance_hz = 2.0f; // ±2Hz tolerance
    float tone_level_db = -10.0f;   // Tone level relative to voice
};

// Regional restrictions for CTCSS tones
enum class Region {
    GLOBAL,           // No restrictions
    UK,              // United Kingdom (50Hz power)
    US,              // United States (60Hz power)
    EU,              // European Union
    NATO,            // NATO countries
    CIVILIAN,        // Civilian use only
    MILITARY         // Military use only
};

// CTCSS tone series
enum class ToneSeries {
    STANDARD,        // Standard 39-tone series
    NATO_MILITARY,   // NATO military series
    EXTENDED,        // Extended series (all tones)
    RESTRICTED       // Region-specific restricted tones
};

class CTCSSSystem {
private:
    static std::unique_ptr<CTCSSSystem> instance;
    static std::mutex instance_mutex;
    
    std::map<float, CTCSSTone> tone_database;
    std::map<std::string, float> pl_code_to_frequency;
    std::map<Region, std::unordered_set<float>> regional_restrictions;
    std::atomic<bool> system_initialized{false};
    
    CTCSSSystem();
    void initializeToneDatabase();
    void setupRegionalRestrictions();
    
public:
    static CTCSSSystem& getInstance();
    static void destroyInstance();
    
    // System initialization
    bool initialize();
    void shutdown();
    bool isInitialized() const { return system_initialized.load(); }
    
    // Tone database access
    std::vector<CTCSSTone> getAllTones() const;
    std::vector<CTCSSTone> getTonesBySeries(ToneSeries series) const;
    std::vector<CTCSSTone> getTonesByRegion(Region region) const;
    CTCSSTone getToneByFrequency(float frequency_hz) const;
    CTCSSTone getToneByPLCode(const std::string& pl_code) const;
    
    // Tone validation
    bool isValidTone(float frequency_hz) const;
    bool isToneAllowedInRegion(float frequency_hz, Region region) const;
    bool isNATOTone(float frequency_hz) const;
    
    // Regional restrictions
    std::vector<float> getRestrictedTonesForRegion(Region region) const;
    bool isToneRestrictedInRegion(float frequency_hz, Region region) const;
    void addRegionalRestriction(float frequency_hz, Region region);
    void removeRegionalRestriction(float frequency_hz, Region region);
    
    // CTCSS configuration
    CTCSSConfig createDefaultConfig() const;
    CTCSSConfig createNATOConfig() const;
    CTCSSConfig createCivilianConfig() const;
    
    // Tone generation and detection
    bool generateCTCSSTone(float frequency_hz, float duration_ms, float sample_rate_hz, 
                          std::vector<float>& output_buffer) const;
    bool detectCTCSSTone(const std::vector<float>& audio_buffer, float sample_rate_hz,
                        float& detected_frequency, float& confidence) const;
    
    // Audio processing
    bool encodeCTCSSTone(const std::vector<float>& voice_audio, float tone_frequency_hz,
                        float sample_rate_hz, std::vector<float>& output_audio) const;
    bool decodeCTCSSTone(const std::vector<float>& audio_input, float expected_tone_hz,
                        float sample_rate_hz, bool& tone_present, float& confidence) const;
    
    // Statistics and monitoring
    struct CTCSSStatistics {
        uint64_t tones_generated = 0;
        uint64_t tones_detected = 0;
        uint64_t decode_attempts = 0;
        uint64_t decode_successes = 0;
        float average_detection_confidence = 0.0f;
        std::map<float, uint64_t> tone_usage_count;
    };
    
    CTCSSStatistics getStatistics() const;
    void resetStatistics();
    
    // Configuration validation
    bool validateConfig(const CTCSSConfig& config) const;
    std::vector<std::string> getConfigErrors(const CTCSSConfig& config) const;
    
    // Utility functions
    std::string frequencyToString(float frequency_hz) const;
    float stringToFrequency(const std::string& frequency_str) const;
    std::vector<std::string> getSupportedPLCodes() const;
    std::vector<float> getSupportedFrequencies() const;
};

// CTCSS API for external access
class CTCSSAPI {
public:
    // Basic CTCSS operations
    static std::string setCTCSSConfig(const CTCSSConfig& config);
    static std::string getCTCSSConfig();
    static std::string enableCTCSS(bool enabled);
    static std::string setTransmitTone(float frequency_hz);
    static std::string setReceiveTone(float frequency_hz);
    
    // Tone database queries
    static std::string getToneInfo(float frequency_hz);
    static std::string getToneInfoByPLCode(const std::string& pl_code);
    static std::string listAvailableTones(Region region = Region::GLOBAL);
    static std::string listNATOTones();
    static std::string listRestrictedTones(Region region);
    
    // Regional restrictions
    static std::string checkRegionalRestrictions(float frequency_hz, Region region);
    static std::string getRegionalRecommendations(Region region);
    
    // Audio processing
    static std::string processAudioWithCTCSS(const std::string& audio_data, 
                                            const CTCSSConfig& config);
    static std::string detectTonesInAudio(const std::string& audio_data);
    
    // Statistics and monitoring
    static std::string getCTCSSStatistics();
    static std::string resetCTCSSStatistics();
    
    // Configuration validation
    static std::string validateCTCSSConfig(const std::string& config_json);
    static std::string getConfigRecommendations(Region region);
};

} // namespace CTCSS

#endif // FGCOM_CTCSS_SYSTEM_H
