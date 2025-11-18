#ifndef FGCOM_FREQUENCY_OFFSET_H
#define FGCOM_FREQUENCY_OFFSET_H

#include <complex>
#include <vector>
#include <memory>
#include <cmath>
#include <algorithm>
#include <mutex>
#include <chrono>
#include <functional>

// Frequency offset configuration
struct FrequencyOffsetConfig {
    bool enable_frequency_offset = true;
    bool enable_donald_duck_effect = true;
    bool enable_doppler_shift = true;
    bool enable_heterodyne_mixing = true;
    float max_offset_hz = 1000.0f;        // Maximum frequency offset in Hz
    float min_offset_hz = -1000.0f;       // Minimum frequency offset in Hz
    float offset_smoothing_factor = 0.1f; // Smoothing factor for offset changes
    bool enable_analog_artifacts = true;  // Enable analog radio artifacts
    bool enable_digital_artifacts = false; // Enable digital radio artifacts
    float sample_rate = 48000.0f;         // Audio sample rate
    int fft_size = 1024;                  // FFT size for processing
    bool enable_real_time_processing = true;
    bool enable_batch_processing = false;
    float processing_latency_ms = 10.0f;  // Maximum processing latency
};

// Frequency offset statistics
struct FrequencyOffsetStats {
    float current_offset_hz;
    float average_offset_hz;
    float peak_offset_hz;
    float offset_variance;
    int total_offsets_applied;
    float processing_time_ms;
    float cpu_usage_percent;
    std::chrono::system_clock::time_point last_update;
    std::vector<float> offset_history;    // Recent offset history
    bool is_processing_active;
    int dropped_samples;
    int processed_samples;
};

// Doppler shift parameters
struct DopplerShiftParams {
    float relative_velocity_mps;          // Relative velocity in m/s
    float carrier_frequency_hz;           // Carrier frequency in Hz
    float speed_of_light_mps = 299792458.0f; // Speed of light in m/s
    bool enable_relativistic_correction = true;
    float atmospheric_refraction_factor = 1.0003f;
};

// Heterodyne mixing parameters
struct HeterodyneMixingParams {
    float local_oscillator_freq_hz;       // Local oscillator frequency
    float intermediate_freq_hz;           // Intermediate frequency
    bool enable_image_rejection = true;
    float image_rejection_db = 40.0f;     // Image rejection in dB
    bool enable_phase_noise = true;
    float phase_noise_db_hz = -80.0f;     // Phase noise in dB/Hz
};

// Main frequency offset processor class
class FGCom_FrequencyOffsetProcessor {
private:
    static std::unique_ptr<FGCom_FrequencyOffsetProcessor> instance;
    static std::mutex instance_mutex;
    
    FrequencyOffsetConfig config;
    FrequencyOffsetStats stats;
    DopplerShiftParams doppler_params;
    HeterodyneMixingParams heterodyne_params;
    
    // Internal processing buffers
    std::vector<std::complex<float>> analytic_signal_buffer;
    std::vector<std::complex<float>> fft_buffer;
    std::vector<std::complex<float>> ifft_buffer;
    std::vector<float> hilbert_buffer;
    std::vector<float> window_function;
    
    // FFT processing
    std::vector<std::complex<float>> fft_twiddle_factors;
    std::vector<int> fft_bit_reverse;
    bool fft_initialized;
    
    // Real-time processing state
    mutable std::mutex processing_mutex;
    bool is_processing;
    float current_offset_hz;
    float target_offset_hz;
    std::chrono::system_clock::time_point last_processing_time;
    
    // Private constructor for singleton
    FGCom_FrequencyOffsetProcessor();
    
public:
    // Singleton access
    static FGCom_FrequencyOffsetProcessor& getInstance();
    static void destroyInstance();
    
    // Main processing methods
    bool applyFrequencyOffset(float* audio_buffer, size_t samples, float offset_hz);
    bool applyDonaldDuckEffect(float* audio_buffer, size_t samples, float offset_hz);
    bool applyDopplerShift(float* audio_buffer, size_t samples, const DopplerShiftParams& params);
    bool applyHeterodyneMixing(float* audio_buffer, size_t samples, const HeterodyneMixingParams& params);
    
    // Advanced processing methods
    bool applyComplexExponentialOffset(float* audio_buffer, size_t samples, float offset_hz);
    bool applyAnalyticSignalOffset(float* audio_buffer, size_t samples, float offset_hz);
    bool applyFFTBasedOffset(float* audio_buffer, size_t samples, float offset_hz);
    bool applyRealTimeOffset(float* audio_buffer, size_t samples, float offset_hz);
    
    // Signal processing utilities
    std::complex<float>* createAnalyticSignal(const float* audio_buffer, size_t samples);
    void extractRealPart(const std::complex<float>* analytic_signal, float* output_buffer, size_t samples);
    void applyHilbertTransform(const float* input, std::complex<float>* output, size_t samples);
    void applyWindowFunction(float* buffer, size_t samples, const std::string& window_type = "hann");
    
    // FFT processing methods
    bool initializeFFT(int fft_size);
    void performFFT(std::complex<float>* data, int size, bool inverse = false);
    void performIFFT(std::complex<float>* data, int size);
    void applyFrequencyShiftFFT(std::complex<float>* fft_data, int size, float offset_hz, float sample_rate);
    
    // Configuration management
    void setConfig(const FrequencyOffsetConfig& new_config);
    FrequencyOffsetConfig getConfig() const;
    bool loadConfigFromFile(const std::string& config_file);
    bool saveConfigToFile(const std::string& config_file) const;
    
    // Doppler shift management
    void setDopplerParams(const DopplerShiftParams& params);
    DopplerShiftParams getDopplerParams() const;
    float calculateDopplerShift(const DopplerShiftParams& params);
    bool updateDopplerShift(float relative_velocity_mps, float carrier_frequency_hz);
    
    // Heterodyne mixing management
    void setHeterodyneParams(const HeterodyneMixingParams& params);
    HeterodyneMixingParams getHeterodyneParams() const;
    bool applyImageRejection(std::complex<float>* signal, size_t samples, float rejection_db);
    bool applyPhaseNoise(std::complex<float>* signal, size_t samples, float noise_db_hz);
    
    // Real-time processing
    bool startRealTimeProcessing();
    bool stopRealTimeProcessing();
    bool isRealTimeProcessingActive() const;
    void setTargetOffset(float offset_hz);
    float getCurrentOffset() const;
    bool updateOffsetSmoothly(float target_offset_hz);
    
    // Statistics and monitoring
    FrequencyOffsetStats getStats() const;
    void resetStats();
    void updateStats();
    bool isProcessingActive() const;
    float getProcessingLatency() const;
    float getCPUUsage() const;
    
    // Audio quality management
    bool setSampleRate(float sample_rate);
    float getSampleRate() const;
    bool setFFTSize(int fft_size);
    int getFFTSize() const;
    bool optimizeForLatency();
    bool optimizeForQuality();
    
    // Error handling and validation
    bool validateOffset(float offset_hz) const;
    bool validateSampleRate(float sample_rate) const;
    bool validateFFTSize(int fft_size) const;
    std::string getLastError() const;
    
    // Callback functions
    void setOffsetChangeCallback(std::function<void(float)> callback);
    void setProcessingCompleteCallback(std::function<void(size_t, float)> callback);
    void setErrorCallback(std::function<void(const std::string&)> callback);
    
private:
    // Internal helper methods
    void initializeBuffers();
    void initializeWindowFunction();
    void initializeFFTTables();
    void updateProcessingStats(size_t samples_processed, float processing_time_ms);
    void logProcessingEvent(const std::string& event);
    void handleProcessingError(const std::string& error);
    
    // FFT helper methods
    void generateTwiddleFactors(int fft_size);
    void generateBitReverseTable(int fft_size);
    void bitReversePermute(std::complex<float>* data, int size);
    void butterflyOperation(std::complex<float>* data, int size, bool inverse);
    
    // Signal processing helper methods
    float calculateHannWindow(int n, int N);
    float calculateHammingWindow(int n, int N);
    float calculateBlackmanWindow(int n, int N);
    void applyLowPassFilter(std::complex<float>* signal, size_t samples, float cutoff_freq, float sample_rate);
    void applyHighPassFilter(std::complex<float>* signal, size_t samples, float cutoff_freq, float sample_rate);
    
    // Error handling
    std::string last_error;
    std::function<void(float)> offset_change_callback;
    std::function<void(size_t, float)> processing_complete_callback;
    std::function<void(const std::string&)> error_callback;
};

// Utility functions for frequency offset processing
namespace FrequencyOffsetUtils {
    // Frequency conversion utilities
    float hzToRadians(float frequency_hz, float sample_rate);
    float radiansToHz(float radians, float sample_rate);
    float normalizeFrequency(float frequency_hz, float sample_rate);
    float denormalizeFrequency(float normalized_freq, float sample_rate);
    
    // Complex number utilities
    std::complex<float> createComplexExponential(float frequency_hz, float time, float sample_rate);
    std::complex<float> createComplexExponential(float frequency_hz, float time);
    float getMagnitude(const std::complex<float>& complex_num);
    float getPhase(const std::complex<float>& complex_num);
    std::complex<float> fromMagnitudePhase(float magnitude, float phase);
    
    // Signal analysis utilities
    float calculateSNR(const float* signal, size_t samples);
    float calculateTHD(const float* signal, size_t samples, float fundamental_freq, float sample_rate);
    float calculateDynamicRange(const float* signal, size_t samples);
    bool detectClipping(const float* signal, size_t samples, float threshold = 0.95f);
    
    // Doppler shift calculations
    float calculateDopplerShift(float relative_velocity_mps, float carrier_frequency_hz, float speed_of_light_mps = 299792458.0f);
    float calculateRelativisticDopplerShift(float relative_velocity_mps, float carrier_frequency_hz);
    float calculateAtmosphericRefractionCorrection(float elevation_angle_deg, float frequency_hz);
    
    // Heterodyne mixing utilities
    std::complex<float> createLocalOscillator(float frequency_hz, float time, float sample_rate);
    void applyMixer(std::complex<float>* signal, const std::complex<float>* lo_signal, size_t samples);
    float calculateImageRejection(float if_freq, float rf_freq, float lo_freq);
    float calculatePhaseNoiseVariance(float phase_noise_db_hz, float bandwidth_hz);
    
    // Audio quality metrics
    float calculateSpectralCentroid(const float* signal, size_t samples, float sample_rate);
    float calculateSpectralRolloff(const float* signal, size_t samples, float sample_rate, float rolloff_percent = 0.85f);
    float calculateSpectralFlux(const float* signal, size_t samples, float sample_rate);
    float calculateZeroCrossingRate(const float* signal, size_t samples);
    
    // Window function utilities
    void generateWindowFunction(float* window, int size, const std::string& window_type);
    float calculateWindowGain(const float* window, int size);
    void applyWindowToSignal(float* signal, const float* window, int size);
    std::string getAvailableWindowTypes();
}

#endif // FGCOM_FREQUENCY_OFFSET_H
