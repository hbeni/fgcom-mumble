#ifndef FGCOM_BFO_SIMULATION_H
#define FGCOM_BFO_SIMULATION_H

#include <vector>
#include <string>
#include <memory>
#include <cmath>
#include <complex>
#include <chrono>
#include <mutex>

// BFO (Beat Frequency Oscillator) configuration
struct BFOConfig {
    float bfo_frequency = 455000.0f;        // BFO frequency in Hz (typically 455 kHz)
    float carrier_frequency = 0.0f;         // Carrier frequency in Hz
    float beat_frequency = 0.0f;            // Beat frequency in Hz
    float bfo_accuracy = 0.1f;              // BFO frequency accuracy in Hz
    float bfo_stability = 0.01f;            // BFO frequency stability (drift per hour)
    bool enable_bfo_drift = true;           // Enable realistic BFO frequency drift
    bool enable_bfo_noise = true;           // Enable BFO phase noise
    float phase_noise_db_hz = -80.0f;       // Phase noise in dB/Hz
    std::chrono::system_clock::time_point last_calibration;
    float temperature_coefficient = 0.001f; // Frequency drift per degree Celsius
    float current_temperature = 25.0f;      // Current temperature in Celsius
};

// BFO statistics and monitoring
struct BFOStats {
    float current_bfo_frequency;
    float frequency_drift_hz;
    float phase_noise_level;
    int total_calibrations;
    std::chrono::system_clock::time_point last_calibration;
    float calibration_accuracy;
    std::vector<float> frequency_history;
    float average_drift_rate;
    bool is_calibrated;
    float temperature_compensation;
};

// Main BFO simulation class
class FGCom_BFO {
private:
    static std::unique_ptr<FGCom_BFO> instance;
    static std::mutex instance_mutex;
    
    BFOConfig config;
    BFOStats stats;
    
    // Internal state
    std::mutex bfo_mutex;
    float current_bfo_frequency;
    float current_beat_frequency;
    float frequency_drift_accumulator;
    std::chrono::system_clock::time_point last_update;
    std::vector<std::complex<float>> bfo_oscillator_buffer;
    std::vector<float> phase_noise_buffer;
    
    // Private constructor for singleton
    FGCom_BFO();
    
public:
    // Singleton access
    static FGCom_BFO& getInstance();
    static void destroyInstance();
    
    // BFO frequency management
    void setBFOFrequency(float freq);
    void setCarrierFrequency(float freq);
    float getBeatFrequency() const;
    float getBFOFrequency() const;
    float getCarrierFrequency() const;
    
    // BFO calibration and stability
    bool calibrateBFO(float reference_frequency);
    void updateTemperature(float temperature_celsius);
    void applyFrequencyDrift();
    float calculateFrequencyDrift();
    
    // Signal processing
    void processSignal(float* input, float* output, size_t samples, float sample_rate);
    void processSignalComplex(std::complex<float>* input, std::complex<float>* output, size_t samples, float sample_rate);
    void generateBFOOscillator(std::complex<float>* output, size_t samples, float sample_rate);
    
    // Beat frequency calculations
    float calculateBeatFrequency(float carrier_freq, float bfo_freq);
    float calculateUpperSidebandBeat(float carrier_freq, float bfo_freq);
    float calculateLowerSidebandBeat(float carrier_freq, float bfo_freq);
    
    // Configuration management
    void setConfig(const BFOConfig& new_config);
    BFOConfig getConfig() const;
    bool loadConfigFromFile(const std::string& config_file);
    bool saveConfigToFile(const std::string& config_file) const;
    
    // Statistics and monitoring
    BFOStats getStats() const;
    void resetStats();
    void updateStats();
    bool isCalibrated() const;
    float getCalibrationAccuracy() const;
    
    // Phase noise and stability
    void generatePhaseNoise(float* noise_buffer, size_t samples, float sample_rate);
    float calculatePhaseNoiseLevel(float bandwidth_hz);
    void applyPhaseNoiseToOscillator(std::complex<float>* oscillator, size_t samples);
    
    // Temperature compensation
    void enableTemperatureCompensation(bool enable);
    bool isTemperatureCompensationEnabled() const;
    float calculateTemperatureDrift(float temperature_celsius);
    
    // Error handling
    std::string getLastError() const;
    void setErrorCallback(std::function<void(const std::string&)> callback);
    
private:
    // Internal helper methods
    void initializeBFO();
    void updateBFOFrequency();
    void logBFOEvent(const std::string& event);
    void handleBFOError(const std::string& error);
    
    // Error handling
    std::string last_error;
    std::function<void(const std::string&)> error_callback;
};

// Multi-mode audio filtering system
class FGCom_AudioFilter {
private:
    static std::unique_ptr<FGCom_AudioFilter> instance;
    static std::mutex instance_mutex;
    
    // Filter configurations for different modes
    struct FilterConfig {
        float cutoff_frequency;
        float bandwidth;
        int filter_order;
        std::string filter_type;
        float ripple_db;
        float stopband_attenuation_db;
    };
    
    std::map<std::string, FilterConfig> filter_configs;
    std::mutex filter_mutex;
    
    // Filter state for each mode
    std::map<std::string, std::vector<float>> filter_states;
    std::map<std::string, std::vector<float>> filter_coefficients;
    
    // Private constructor for singleton
    FGCom_AudioFilter();
    
public:
    // Singleton access
    static FGCom_AudioFilter& getInstance();
    static void destroyInstance();
    
    // Mode-specific filter applications
    void applySSBFilter(float* audio, size_t samples, float sample_rate);
    void applyAMFilter(float* audio, size_t samples, float sample_rate);
    void applyCWFilter(float* audio, size_t samples, float sample_rate);
    void applyAviationFilter(float* audio, size_t samples, float sample_rate);
    void applyMaritimeFilter(float* audio, size_t samples, float sample_rate);
    void applyNotchFilter(float* audio, size_t samples, float notch_freq, float sample_rate);
    
    // Dynamic filter selection
    void applyModeSpecificFilter(float* audio, size_t samples, const std::string& mode, float sample_rate);
    void applyBandSpecificFilter(float* audio, size_t samples, const std::string& band, float sample_rate);
    
    // Filter configuration
    void setFilterConfig(const std::string& mode, const FilterConfig& config);
    FilterConfig getFilterConfig(const std::string& mode) const;
    void initializeDefaultFilters();
    
    // Advanced filtering
    void applyAdaptiveFilter(float* audio, size_t samples, float sample_rate, float signal_quality);
    void applyDynamicNotchFilter(float* audio, size_t samples, float sample_rate, const std::vector<float>& interference_freqs);
    void applyBandpassFilter(float* audio, size_t samples, float low_cutoff, float high_cutoff, float sample_rate);
    void applyHighpassFilter(float* audio, size_t samples, float cutoff_freq, float sample_rate);
    void applyLowpassFilter(float* audio, size_t samples, float cutoff_freq, float sample_rate);
    
    // Filter analysis
    float calculateFilterResponse(float frequency, const std::string& mode);
    void analyzeFilterPerformance(float* audio, size_t samples, const std::string& mode);
    float calculateFilteredSNR(float* original, float* filtered, size_t samples);
    
    // Filter state management
    void resetFilterState(const std::string& mode);
    void resetAllFilterStates();
    bool isFilterInitialized(const std::string& mode) const;
    
private:
    // Internal filter implementation
    void applyIIRFilter(float* audio, size_t samples, const std::vector<float>& b_coeffs, const std::vector<float>& a_coeffs, std::vector<float>& state);
    void applyFIRFilter(float* audio, size_t samples, const std::vector<float>& coefficients, std::vector<float>& state);
    void designButterworthFilter(float cutoff_freq, float sample_rate, int order, std::vector<float>& b_coeffs, std::vector<float>& a_coeffs);
    void designChebyshevFilter(float cutoff_freq, float sample_rate, int order, float ripple_db, std::vector<float>& b_coeffs, std::vector<float>& a_coeffs);
    void designEllipticFilter(float cutoff_freq, float sample_rate, int order, float ripple_db, float stopband_attenuation, std::vector<float>& b_coeffs, std::vector<float>& a_coeffs);
};

// Fuzzy logic propagation modeling
struct PropagationAnomaly {
    std::string type;                    // "sporadic_e", "unexpected_opening", "band_closing"
    float frequency_mhz;                 // Affected frequency
    double latitude;                     // Location latitude
    double longitude;                    // Location longitude
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    float intensity;                     // Anomaly intensity (0.0-1.0)
    std::string description;             // Human-readable description
    bool is_active;                      // Currently active
    float confidence_level;              // Confidence in anomaly detection (0.0-1.0)
};

class FGCom_FuzzyPropagation {
private:
    static std::unique_ptr<FGCom_FuzzyPropagation> instance;
    static std::mutex instance_mutex;
    
    float unpredictability_factor;
    std::vector<PropagationAnomaly> recent_anomalies;
    std::vector<PropagationAnomaly> active_anomalies;
    
    // Fuzzy logic parameters
    struct FuzzyParameters {
        float sporadic_e_probability = 0.1f;      // Probability of sporadic E-skip
        float unexpected_opening_probability = 0.05f; // Probability of unexpected band opening
        float band_closing_probability = 0.02f;   // Probability of band closing
        float solar_maximum_factor = 1.5f;        // Solar maximum enhancement factor
        float seasonal_variation = 0.3f;          // Seasonal variation factor
        float time_of_day_factor = 0.2f;          // Time of day variation
        float geographic_factor = 0.4f;           // Geographic location factor
    };
    
    FuzzyParameters fuzzy_params;
    std::mutex fuzzy_mutex;
    
    // Private constructor for singleton
    FGCom_FuzzyPropagation();
    
public:
    // Singleton access
    static FGCom_FuzzyPropagation& getInstance();
    static void destroyInstance();
    
    // Anomaly management
    void addAnomaly(const PropagationAnomaly& anomaly);
    void removeAnomaly(const std::string& anomaly_id);
    std::vector<PropagationAnomaly> getActiveAnomalies() const;
    std::vector<PropagationAnomaly> getRecentAnomalies() const;
    
    // Fuzzy logic calculations
    float calculateUnpredictabilityFactor();
    void adjustPropagationModel(float factor);
    float calculateAnomalyProbability(const std::string& anomaly_type, double lat, double lon, float freq);
    float calculateSporadicEProbability(double lat, double lon, float freq, const std::chrono::system_clock::time_point& time);
    float calculateUnexpectedOpeningProbability(double lat, double lon, float freq, const std::chrono::system_clock::time_point& time);
    
    // Anomaly detection
    bool detectSporadicESkip(double lat, double lon, float freq);
    bool detectUnexpectedBandOpening(double lat, double lon, float freq);
    bool detectBandClosing(double lat, double lon, float freq);
    void updateAnomalyStatus();
    
    // Fuzzy logic inference
    float fuzzyInference(float input_value, const std::string& input_variable, const std::string& output_variable);
    float calculateMembershipFunction(float value, float center, float width, const std::string& shape);
    std::vector<float> defuzzify(const std::vector<float>& fuzzy_outputs, const std::vector<float>& weights);
    
    // Configuration management
    void setFuzzyParameters(const FuzzyParameters& params);
    FuzzyParameters getFuzzyParameters() const;
    void loadAnomalyDatabase(const std::string& database_file);
    void saveAnomalyDatabase(const std::string& database_file) const;
    
    // Statistics and monitoring
    int getActiveAnomalyCount() const;
    int getTotalAnomalyCount() const;
    float getAverageAnomalyIntensity() const;
    std::chrono::system_clock::time_point getLastAnomalyTime() const;
    
    // Real-time anomaly processing
    void processRealTimeData(double lat, double lon, float freq, float signal_quality);
    void updateAnomalyProbabilities();
    void generateAnomalyPredictions();
    
private:
    // Internal helper methods
    void initializeFuzzySystem();
    void updateAnomalyDatabase();
    void logAnomalyEvent(const PropagationAnomaly& anomaly);
    bool isAnomalyActive(const PropagationAnomaly& anomaly) const;
    void cleanupExpiredAnomalies();
    
    // Fuzzy logic helper functions
    float calculateSporadicEFactors(double lat, double lon, float freq, const std::chrono::system_clock::time_point& time);
    float calculateSolarActivityFactor(const std::chrono::system_clock::time_point& time);
    float calculateSeasonalFactor(const std::chrono::system_clock::time_point& time);
    float calculateGeographicFactor(double lat, double lon);
};

// Utility functions for BFO and filtering
namespace BFOUtils {
    // BFO frequency calculations
    float calculateBFOFrequency(float carrier_freq, float beat_freq, bool upper_sideband = true);
    float calculateCarrierFrequency(float bfo_freq, float beat_freq, bool upper_sideband = true);
    float calculateBeatFrequency(float carrier_freq, float bfo_freq);
    
    // Filter design utilities
    std::vector<float> designLowpassFilter(float cutoff_freq, float sample_rate, int order);
    std::vector<float> designHighpassFilter(float cutoff_freq, float sample_rate, int order);
    std::vector<float> designBandpassFilter(float low_cutoff, float high_cutoff, float sample_rate, int order);
    std::vector<float> designNotchFilter(float notch_freq, float sample_rate, int order, float q_factor = 10.0f);
    
    // Frequency conversion utilities
    float hzToRadians(float frequency_hz, float sample_rate);
    float radiansToHz(float radians, float sample_rate);
    float normalizeFrequency(float frequency_hz, float sample_rate);
    
    // Signal processing utilities
    void applyFilter(float* signal, size_t samples, const std::vector<float>& coefficients, std::vector<float>& state);
    float calculateFilterGain(float frequency, const std::vector<float>& b_coeffs, const std::vector<float>& a_coeffs, float sample_rate);
    void analyzeFilterResponse(const std::vector<float>& b_coeffs, const std::vector<float>& a_coeffs, float sample_rate, size_t num_points = 1024);
    
    // BFO stability calculations
    float calculateFrequencyStability(float temperature, float time_hours, float temperature_coefficient);
    float calculatePhaseNoiseVariance(float phase_noise_db_hz, float bandwidth_hz);
    float calculateBFOAccuracy(float reference_frequency, float measured_frequency);
}

#endif // FGCOM_BFO_SIMULATION_H
