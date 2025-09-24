#include "frequency_offset.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>

// Singleton instance
std::unique_ptr<FGCom_FrequencyOffsetProcessor> FGCom_FrequencyOffsetProcessor::instance = nullptr;
std::mutex FGCom_FrequencyOffsetProcessor::instance_mutex;

// Constructor
FGCom_FrequencyOffsetProcessor::FGCom_FrequencyOffsetProcessor() 
    : fft_initialized(false)
    , is_processing(false)
    , current_offset_hz(0.0f)
    , target_offset_hz(0.0f)
    , last_processing_time(std::chrono::system_clock::now())
{
    // Initialize statistics
    stats.current_offset_hz = 0.0f;
    stats.average_offset_hz = 0.0f;
    stats.peak_offset_hz = 0.0f;
    stats.offset_variance = 0.0f;
    stats.total_offsets_applied = 0;
    stats.processing_time_ms = 0.0f;
    stats.cpu_usage_percent = 0.0f;
    stats.last_update = std::chrono::system_clock::now();
    stats.is_processing_active = false;
    stats.dropped_samples = 0;
    stats.processed_samples = 0;
    
    // Initialize buffers
    initializeBuffers();
    initializeWindowFunction();
}

// Singleton access
FGCom_FrequencyOffsetProcessor& FGCom_FrequencyOffsetProcessor::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::unique_ptr<FGCom_FrequencyOffsetProcessor>(new FGCom_FrequencyOffsetProcessor());
    }
    return *instance;
}

void FGCom_FrequencyOffsetProcessor::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    instance.reset();
}

// Main processing methods
bool FGCom_FrequencyOffsetProcessor::applyFrequencyOffset(float* audio_buffer, size_t samples, float offset_hz) {
    if (!validateOffset(offset_hz)) {
        handleProcessingError("Invalid frequency offset: " + std::to_string(offset_hz));
        return false;
    }
    
    if (!validateSampleRate(config.sample_rate)) {
        handleProcessingError("Invalid sample rate: " + std::to_string(config.sample_rate));
        return false;
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    bool success = false;
    if (config.enable_real_time_processing) {
        success = applyRealTimeOffset(audio_buffer, samples, offset_hz);
    } else {
        success = applyComplexExponentialOffset(audio_buffer, samples, offset_hz);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    float processing_time_ms = duration.count() / 1000.0f;
    
    if (success) {
        updateProcessingStats(samples, processing_time_ms);
        current_offset_hz = offset_hz;
        
        if (processing_complete_callback) {
            processing_complete_callback(samples, processing_time_ms);
        }
    }
    
    return success;
}

bool FGCom_FrequencyOffsetProcessor::applyDonaldDuckEffect(float* audio_buffer, size_t samples, float offset_hz) {
    if (!config.enable_donald_duck_effect) {
        return true; // Effect disabled
    }
    
    // Donald Duck effect is achieved by applying a frequency offset
    // The "Donald Duck" sound comes from shifting the frequency up
    float donald_duck_offset = std::abs(offset_hz);
    if (offset_hz < 0) {
        donald_duck_offset = -donald_duck_offset; // Maintain direction
    }
    
    return applyFrequencyOffset(audio_buffer, samples, donald_duck_offset);
}

bool FGCom_FrequencyOffsetProcessor::applyDopplerShift(float* audio_buffer, size_t samples, const DopplerShiftParams& params) {
    if (!config.enable_doppler_shift) {
        return true; // Doppler shift disabled
    }
    
    float doppler_offset = calculateDopplerShift(params);
    return applyFrequencyOffset(audio_buffer, samples, doppler_offset);
}

bool FGCom_FrequencyOffsetProcessor::applyHeterodyneMixing(float* audio_buffer, size_t samples, const HeterodyneMixingParams& params) {
    if (!config.enable_heterodyne_mixing) {
        return true; // Heterodyne mixing disabled
    }
    
    // Create local oscillator signal
    std::vector<std::complex<float>> lo_signal(samples);
    for (size_t i = 0; i < samples; i++) {
        float time = static_cast<float>(i) / config.sample_rate;
        lo_signal[i] = FrequencyOffsetUtils::createLocalOscillator(params.local_oscillator_freq_hz, time, config.sample_rate);
    }
    
    // Create analytic signal
    std::complex<float>* analytic_signal = createAnalyticSignal(audio_buffer, samples);
    if (!analytic_signal) {
        return false;
    }
    
    // Apply mixing
    FrequencyOffsetUtils::applyMixer(analytic_signal, lo_signal.data(), samples);
    
    // Apply image rejection if enabled
    if (params.enable_image_rejection) {
        applyImageRejection(analytic_signal, samples, params.image_rejection_db);
    }
    
    // Apply phase noise if enabled
    if (params.enable_phase_noise) {
        applyPhaseNoise(analytic_signal, samples, params.phase_noise_db_hz);
    }
    
    // Extract real part
    extractRealPart(analytic_signal, audio_buffer, samples);
    
    delete[] analytic_signal;
    return true;
}

// Advanced processing methods
bool FGCom_FrequencyOffsetProcessor::applyComplexExponentialOffset(float* audio_buffer, size_t samples, float offset_hz) {
    // Create analytic signal using Hilbert transform
    std::complex<float>* analytic_signal = createAnalyticSignal(audio_buffer, samples);
    if (!analytic_signal) {
        return false;
    }
    
    // Apply frequency shift by complex multiplication
    for (size_t i = 0; i < samples; i++) {
        float time = static_cast<float>(i) / config.sample_rate;
        std::complex<float> shift = std::exp(std::complex<float>(0, 2 * M_PI * offset_hz * time));
        analytic_signal[i] *= shift;
    }
    
    // Extract real part for output
    extractRealPart(analytic_signal, audio_buffer, samples);
    
    delete[] analytic_signal;
    return true;
}

bool FGCom_FrequencyOffsetProcessor::applyAnalyticSignalOffset(float* audio_buffer, size_t samples, float offset_hz) {
    // Ensure buffer is large enough
    if (analytic_signal_buffer.size() < samples) {
        analytic_signal_buffer.resize(samples);
    }
    
    // Create analytic signal
    std::complex<float>* analytic_signal = createAnalyticSignal(audio_buffer, samples);
    if (!analytic_signal) {
        return false;
    }
    
    // Copy to buffer
    std::copy(analytic_signal, analytic_signal + samples, analytic_signal_buffer.begin());
    
    // Apply frequency shift
    for (size_t i = 0; i < samples; i++) {
        float time = static_cast<float>(i) / config.sample_rate;
        std::complex<float> shift = FrequencyOffsetUtils::createComplexExponential(offset_hz, time, config.sample_rate);
        analytic_signal_buffer[i] *= shift;
    }
    
    // Extract real part
    extractRealPart(analytic_signal_buffer.data(), audio_buffer, samples);
    
    delete[] analytic_signal;
    return true;
}

bool FGCom_FrequencyOffsetProcessor::applyFFTBasedOffset(float* audio_buffer, size_t samples, float offset_hz) {
    if (!fft_initialized) {
        if (!initializeFFT(config.fft_size)) {
            return false;
        }
    }
    
    // Ensure FFT buffer is large enough
    if (fft_buffer.size() < static_cast<size_t>(config.fft_size)) {
        fft_buffer.resize(config.fft_size);
        ifft_buffer.resize(config.fft_size);
    }
    
    // Copy input to FFT buffer
    std::fill(fft_buffer.begin(), fft_buffer.end(), std::complex<float>(0, 0));
    for (size_t i = 0; i < std::min(samples, static_cast<size_t>(config.fft_size)); i++) {
        fft_buffer[i] = std::complex<float>(audio_buffer[i], 0);
    }
    
    // Apply window function
    applyWindowFunction(reinterpret_cast<float*>(fft_buffer.data()), config.fft_size);
    
    // Perform FFT
    performFFT(fft_buffer.data(), config.fft_size);
    
    // Apply frequency shift in frequency domain
    applyFrequencyShiftFFT(fft_buffer.data(), config.fft_size, offset_hz, config.sample_rate);
    
    // Perform IFFT
    performIFFT(fft_buffer.data(), config.fft_size);
    
    // Copy result back to output buffer
    for (size_t i = 0; i < std::min(samples, static_cast<size_t>(config.fft_size)); i++) {
        audio_buffer[i] = fft_buffer[i].real();
    }
    
    return true;
}

bool FGCom_FrequencyOffsetProcessor::applyRealTimeOffset(float* audio_buffer, size_t samples, float offset_hz) {
    std::lock_guard<std::mutex> lock(processing_mutex);
    
    if (!is_processing) {
        return false;
    }
    
    // Smooth offset changes for real-time processing
    if (config.offset_smoothing_factor > 0.0f) {
        target_offset_hz = offset_hz;
        float offset_diff = target_offset_hz - current_offset_hz;
        current_offset_hz += offset_diff * config.offset_smoothing_factor;
        offset_hz = current_offset_hz;
    }
    
    // Use complex exponential method for real-time processing
    return applyComplexExponentialOffset(audio_buffer, samples, offset_hz);
}

// Signal processing utilities
std::complex<float>* FGCom_FrequencyOffsetProcessor::createAnalyticSignal(const float* audio_buffer, size_t samples) {
    std::complex<float>* analytic_signal = new std::complex<float>[samples];
    if (!analytic_signal) {
        return nullptr;
    }
    
    // Apply Hilbert transform to create analytic signal
    applyHilbertTransform(audio_buffer, analytic_signal, samples);
    
    return analytic_signal;
}

void FGCom_FrequencyOffsetProcessor::extractRealPart(const std::complex<float>* analytic_signal, float* output_buffer, size_t samples) {
    for (size_t i = 0; i < samples; i++) {
        output_buffer[i] = analytic_signal[i].real();
    }
}

void FGCom_FrequencyOffsetProcessor::applyHilbertTransform(const float* input, std::complex<float>* output, size_t samples) {
    // Simple Hilbert transform implementation
    // For production use, a more sophisticated FFT-based implementation would be better
    
    for (size_t i = 0; i < samples; i++) {
        float real_part = input[i];
        float imag_part = 0.0f;
        
        // Calculate Hilbert transform (simplified)
        if (i > 0 && i < samples - 1) {
            imag_part = (input[i + 1] - input[i - 1]) / 2.0f;
        }
        
        output[i] = std::complex<float>(real_part, imag_part);
    }
}

void FGCom_FrequencyOffsetProcessor::applyWindowFunction(float* buffer, size_t samples, const std::string& window_type) {
    if (window_function.size() < samples) {
        window_function.resize(samples);
        FrequencyOffsetUtils::generateWindowFunction(window_function.data(), samples, window_type);
    }
    
    for (size_t i = 0; i < samples; i++) {
        buffer[i] *= window_function[i];
    }
}

// FFT processing methods
bool FGCom_FrequencyOffsetProcessor::initializeFFT(int fft_size) {
    if (fft_size <= 0 || (fft_size & (fft_size - 1)) != 0) {
        handleProcessingError("Invalid FFT size: " + std::to_string(fft_size));
        return false;
    }
    
    config.fft_size = fft_size;
    initializeFFTTables();
    fft_initialized = true;
    
    return true;
}

void FGCom_FrequencyOffsetProcessor::performFFT(std::complex<float>* data, int size, bool inverse) {
    if (!fft_initialized) {
        return;
    }
    
    // Bit-reverse permutation
    bitReversePermute(data, size);
    
    // Butterfly operations
    butterflyOperation(data, size, inverse);
    
    // Scale for inverse FFT
    if (inverse) {
        for (int i = 0; i < size; i++) {
            data[i] /= static_cast<float>(size);
        }
    }
}

void FGCom_FrequencyOffsetProcessor::performIFFT(std::complex<float>* data, int size) {
    performFFT(data, size, true);
}

void FGCom_FrequencyOffsetProcessor::applyFrequencyShiftFFT(std::complex<float>* fft_data, int size, float offset_hz, float sample_rate) {
    float bin_freq = sample_rate / size;
    int shift_bins = static_cast<int>(offset_hz / bin_freq);
    
    // Apply circular shift
    if (shift_bins > 0) {
        std::rotate(fft_data, fft_data + shift_bins, fft_data + size);
    } else if (shift_bins < 0) {
        std::rotate(fft_data, fft_data + size + shift_bins, fft_data + size);
    }
}

// Configuration management
void FGCom_FrequencyOffsetProcessor::setConfig(const FrequencyOffsetConfig& new_config) {
    std::lock_guard<std::mutex> lock(processing_mutex);
    config = new_config;
    
    // Reinitialize if necessary
    if (config.fft_size != static_cast<int>(fft_buffer.size())) {
        fft_initialized = false;
    }
}

FrequencyOffsetConfig FGCom_FrequencyOffsetProcessor::getConfig() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return config;
}

bool FGCom_FrequencyOffsetProcessor::loadConfigFromFile(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    std::string current_section = "";
    
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        if (line[0] == '[' && line.back() == ']') {
            current_section = line.substr(1, line.length() - 2);
            continue;
        }
        
        size_t equal_pos = line.find('=');
        if (equal_pos != std::string::npos) {
            std::string key = line.substr(0, equal_pos);
            std::string value = line.substr(equal_pos + 1);
            
            if (current_section == "frequency_offset") {
                if (key == "enable_frequency_offset") {
                    config.enable_frequency_offset = (value == "true");
                } else if (key == "enable_donald_duck_effect") {
                    config.enable_donald_duck_effect = (value == "true");
                } else if (key == "max_offset_hz") {
                    config.max_offset_hz = std::stof(value);
                } else if (key == "min_offset_hz") {
                    config.min_offset_hz = std::stof(value);
                } else if (key == "sample_rate") {
                    config.sample_rate = std::stof(value);
                } else if (key == "fft_size") {
                    config.fft_size = std::stoi(value);
                }
            }
        }
    }
    
    return true;
}

bool FGCom_FrequencyOffsetProcessor::saveConfigToFile(const std::string& config_file) const {
    std::ofstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    file << "[frequency_offset]" << std::endl;
    file << "enable_frequency_offset=" << (config.enable_frequency_offset ? "true" : "false") << std::endl;
    file << "enable_donald_duck_effect=" << (config.enable_donald_duck_effect ? "true" : "false") << std::endl;
    file << "enable_doppler_shift=" << (config.enable_doppler_shift ? "true" : "false") << std::endl;
    file << "enable_heterodyne_mixing=" << (config.enable_heterodyne_mixing ? "true" : "false") << std::endl;
    file << "max_offset_hz=" << config.max_offset_hz << std::endl;
    file << "min_offset_hz=" << config.min_offset_hz << std::endl;
    file << "offset_smoothing_factor=" << config.offset_smoothing_factor << std::endl;
    file << "sample_rate=" << config.sample_rate << std::endl;
    file << "fft_size=" << config.fft_size << std::endl;
    file << "enable_real_time_processing=" << (config.enable_real_time_processing ? "true" : "false") << std::endl;
    file << "processing_latency_ms=" << config.processing_latency_ms << std::endl;
    
    return true;
}

// Doppler shift management
void FGCom_FrequencyOffsetProcessor::setDopplerParams(const DopplerShiftParams& params) {
    std::lock_guard<std::mutex> lock(processing_mutex);
    doppler_params = params;
}

DopplerShiftParams FGCom_FrequencyOffsetProcessor::getDopplerParams() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return doppler_params;
}

float FGCom_FrequencyOffsetProcessor::calculateDopplerShift(const DopplerShiftParams& params) {
    return FrequencyOffsetUtils::calculateDopplerShift(
        params.relative_velocity_mps,
        params.carrier_frequency_hz,
        params.speed_of_light_mps
    );
}

bool FGCom_FrequencyOffsetProcessor::updateDopplerShift(float relative_velocity_mps, float carrier_frequency_hz) {
    std::lock_guard<std::mutex> lock(processing_mutex);
    doppler_params.relative_velocity_mps = relative_velocity_mps;
    doppler_params.carrier_frequency_hz = carrier_frequency_hz;
    return true;
}

// Heterodyne mixing management
void FGCom_FrequencyOffsetProcessor::setHeterodyneParams(const HeterodyneMixingParams& params) {
    std::lock_guard<std::mutex> lock(processing_mutex);
    heterodyne_params = params;
}

HeterodyneMixingParams FGCom_FrequencyOffsetProcessor::getHeterodyneParams() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return heterodyne_params;
}

bool FGCom_FrequencyOffsetProcessor::applyImageRejection(std::complex<float>* signal, size_t samples, float rejection_db) {
    // Simple image rejection filter
    float rejection_factor = pow(10.0f, -rejection_db / 20.0f);
    
    for (size_t i = 0; i < samples; i++) {
        // Apply low-pass filtering to reduce image components
        if (i > 0) {
            signal[i] = signal[i] * (1.0f - rejection_factor) + signal[i-1] * rejection_factor;
        }
    }
    
    return true;
}

bool FGCom_FrequencyOffsetProcessor::applyPhaseNoise(std::complex<float>* signal, size_t samples, float noise_db_hz) {
    // Simple phase noise model
    float noise_variance = FrequencyOffsetUtils::calculatePhaseNoiseVariance(noise_db_hz, config.sample_rate);
    
    for (size_t i = 0; i < samples; i++) {
        // Generate random phase noise
        float phase_noise = (static_cast<float>(rand()) / RAND_MAX - 0.5f) * 2.0f * sqrt(noise_variance);
        
        // Apply phase noise
        std::complex<float> noise_rotation = std::exp(std::complex<float>(0, phase_noise));
        signal[i] *= noise_rotation;
    }
    
    return true;
}

// Real-time processing
bool FGCom_FrequencyOffsetProcessor::startRealTimeProcessing() {
    std::lock_guard<std::mutex> lock(processing_mutex);
    is_processing = true;
    stats.is_processing_active = true;
    return true;
}

bool FGCom_FrequencyOffsetProcessor::stopRealTimeProcessing() {
    std::lock_guard<std::mutex> lock(processing_mutex);
    is_processing = false;
    stats.is_processing_active = false;
    return true;
}

bool FGCom_FrequencyOffsetProcessor::isRealTimeProcessingActive() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return is_processing;
}

void FGCom_FrequencyOffsetProcessor::setTargetOffset(float offset_hz) {
    std::lock_guard<std::mutex> lock(processing_mutex);
    target_offset_hz = offset_hz;
}

float FGCom_FrequencyOffsetProcessor::getCurrentOffset() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return current_offset_hz;
}

bool FGCom_FrequencyOffsetProcessor::updateOffsetSmoothly(float target_offset_hz) {
    std::lock_guard<std::mutex> lock(processing_mutex);
    
    if (config.offset_smoothing_factor <= 0.0f) {
        current_offset_hz = target_offset_hz;
        return true;
    }
    
    float offset_diff = target_offset_hz - current_offset_hz;
    current_offset_hz += offset_diff * config.offset_smoothing_factor;
    
    if (offset_change_callback) {
        offset_change_callback(current_offset_hz);
    }
    
    return true;
}

// Statistics and monitoring
FrequencyOffsetStats FGCom_FrequencyOffsetProcessor::getStats() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return stats;
}

void FGCom_FrequencyOffsetProcessor::resetStats() {
    std::lock_guard<std::mutex> lock(processing_mutex);
    stats = FrequencyOffsetStats();
    stats.last_update = std::chrono::system_clock::now();
}

void FGCom_FrequencyOffsetProcessor::updateStats() {
    std::lock_guard<std::mutex> lock(processing_mutex);
    
    // Update average offset
    if (stats.total_offsets_applied > 0) {
        stats.average_offset_hz = (stats.average_offset_hz * (stats.total_offsets_applied - 1) + 
                                   current_offset_hz) / stats.total_offsets_applied;
    }
    
    // Update peak offset
    stats.peak_offset_hz = std::max(stats.peak_offset_hz, std::abs(current_offset_hz));
    
    // Update offset history
    stats.offset_history.push_back(current_offset_hz);
    if (stats.offset_history.size() > 100) {
        stats.offset_history.erase(stats.offset_history.begin());
    }
    
    // Calculate variance
    if (stats.offset_history.size() > 1) {
        float sum = 0.0f;
        for (float offset : stats.offset_history) {
            sum += offset;
        }
        float mean = sum / stats.offset_history.size();
        
        float variance_sum = 0.0f;
        for (float offset : stats.offset_history) {
            variance_sum += (offset - mean) * (offset - mean);
        }
        stats.offset_variance = variance_sum / stats.offset_history.size();
    }
}

bool FGCom_FrequencyOffsetProcessor::isProcessingActive() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return stats.is_processing_active;
}

float FGCom_FrequencyOffsetProcessor::getProcessingLatency() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return stats.processing_time_ms;
}

float FGCom_FrequencyOffsetProcessor::getCPUUsage() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return stats.cpu_usage_percent;
}

// Audio quality management
bool FGCom_FrequencyOffsetProcessor::setSampleRate(float sample_rate) {
    if (!validateSampleRate(sample_rate)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(processing_mutex);
    config.sample_rate = sample_rate;
    return true;
}

float FGCom_FrequencyOffsetProcessor::getSampleRate() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return config.sample_rate;
}

bool FGCom_FrequencyOffsetProcessor::setFFTSize(int fft_size) {
    if (!validateFFTSize(fft_size)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(processing_mutex);
    config.fft_size = fft_size;
    fft_initialized = false;
    return true;
}

int FGCom_FrequencyOffsetProcessor::getFFTSize() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return config.fft_size;
}

bool FGCom_FrequencyOffsetProcessor::optimizeForLatency() {
    std::lock_guard<std::mutex> lock(processing_mutex);
    config.enable_real_time_processing = true;
    config.enable_batch_processing = false;
    config.processing_latency_ms = 5.0f;
    config.fft_size = 512; // Smaller FFT for lower latency
    return true;
}

bool FGCom_FrequencyOffsetProcessor::optimizeForQuality() {
    std::lock_guard<std::mutex> lock(processing_mutex);
    config.enable_real_time_processing = false;
    config.enable_batch_processing = true;
    config.processing_latency_ms = 50.0f;
    config.fft_size = 2048; // Larger FFT for better quality
    return true;
}

// Error handling and validation
bool FGCom_FrequencyOffsetProcessor::validateOffset(float offset_hz) const {
    return offset_hz >= config.min_offset_hz && offset_hz <= config.max_offset_hz;
}

bool FGCom_FrequencyOffsetProcessor::validateSampleRate(float sample_rate) const {
    return sample_rate > 0.0f && sample_rate <= 192000.0f;
}

bool FGCom_FrequencyOffsetProcessor::validateFFTSize(int fft_size) const {
    return fft_size > 0 && (fft_size & (fft_size - 1)) == 0; // Power of 2
}

std::string FGCom_FrequencyOffsetProcessor::getLastError() const {
    std::lock_guard<std::mutex> lock(processing_mutex);
    return last_error;
}

// Callback functions
void FGCom_FrequencyOffsetProcessor::setOffsetChangeCallback(std::function<void(float)> callback) {
    std::lock_guard<std::mutex> lock(processing_mutex);
    offset_change_callback = callback;
}

void FGCom_FrequencyOffsetProcessor::setProcessingCompleteCallback(std::function<void(size_t, float)> callback) {
    std::lock_guard<std::mutex> lock(processing_mutex);
    processing_complete_callback = callback;
}

void FGCom_FrequencyOffsetProcessor::setErrorCallback(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(processing_mutex);
    error_callback = callback;
}

// Private helper methods
void FGCom_FrequencyOffsetProcessor::initializeBuffers() {
    // Initialize processing buffers
    analytic_signal_buffer.resize(config.fft_size);
    fft_buffer.resize(config.fft_size);
    ifft_buffer.resize(config.fft_size);
    hilbert_buffer.resize(config.fft_size);
    window_function.resize(config.fft_size);
}

void FGCom_FrequencyOffsetProcessor::initializeWindowFunction() {
    FrequencyOffsetUtils::generateWindowFunction(window_function.data(), config.fft_size, "hann");
}

void FGCom_FrequencyOffsetProcessor::initializeFFTTables() {
    generateTwiddleFactors(config.fft_size);
    generateBitReverseTable(config.fft_size);
}

void FGCom_FrequencyOffsetProcessor::updateProcessingStats(size_t samples_processed, float processing_time_ms) {
    stats.total_offsets_applied++;
    stats.processed_samples += samples_processed;
    stats.processing_time_ms = processing_time_ms;
    stats.last_update = std::chrono::system_clock::now();
    
    // Calculate CPU usage (simplified)
    float target_time_ms = (samples_processed / config.sample_rate) * 1000.0f;
    stats.cpu_usage_percent = (processing_time_ms / target_time_ms) * 100.0f;
}

void FGCom_FrequencyOffsetProcessor::logProcessingEvent(const std::string& event) {
    if (config.enable_real_time_processing) {
        std::cout << "[FrequencyOffset] " << event << std::endl;
    }
}

void FGCom_FrequencyOffsetProcessor::handleProcessingError(const std::string& error) {
    last_error = error;
    logProcessingEvent("Error: " + error);
    
    if (error_callback) {
        error_callback(error);
    }
}

// FFT helper methods
void FGCom_FrequencyOffsetProcessor::generateTwiddleFactors(int fft_size) {
    fft_twiddle_factors.resize(fft_size / 2);
    for (int i = 0; i < fft_size / 2; i++) {
        float angle = -2.0f * M_PI * i / fft_size;
        fft_twiddle_factors[i] = std::complex<float>(cos(angle), sin(angle));
    }
}

void FGCom_FrequencyOffsetProcessor::generateBitReverseTable(int fft_size) {
    fft_bit_reverse.resize(fft_size);
    int log2n = static_cast<int>(log2(fft_size));
    
    for (int i = 0; i < fft_size; i++) {
        int reversed = 0;
        int temp = i;
        for (int j = 0; j < log2n; j++) {
            reversed = (reversed << 1) | (temp & 1);
            temp >>= 1;
        }
        fft_bit_reverse[i] = reversed;
    }
}

void FGCom_FrequencyOffsetProcessor::bitReversePermute(std::complex<float>* data, int size) {
    for (int i = 0; i < size; i++) {
        int j = fft_bit_reverse[i];
        if (i < j) {
            std::swap(data[i], data[j]);
        }
    }
}

void FGCom_FrequencyOffsetProcessor::butterflyOperation(std::complex<float>* data, int size, bool inverse) {
    // Note: sign variable removed as it's not used in the current implementation
    // The FFT implementation uses twiddle factors directly
    
    for (int len = 2; len <= size; len <<= 1) {
        int step = size / len;
        for (int i = 0; i < size; i += len) {
            for (int j = 0; j < len / 2; j++) {
                int u = i + j;
                int v = i + j + len / 2;
                std::complex<float> w = fft_twiddle_factors[j * step];
                if (inverse) {
                    w = std::conj(w);
                }
                
                std::complex<float> temp = data[v] * w;
                data[v] = data[u] - temp;
                data[u] = data[u] + temp;
            }
        }
    }
}

// Signal processing helper methods
float FGCom_FrequencyOffsetProcessor::calculateHannWindow(int n, int N) {
    return 0.5f * (1.0f - cos(2.0f * M_PI * n / (N - 1)));
}

float FGCom_FrequencyOffsetProcessor::calculateHammingWindow(int n, int N) {
    return 0.54f - 0.46f * cos(2.0f * M_PI * n / (N - 1));
}

float FGCom_FrequencyOffsetProcessor::calculateBlackmanWindow(int n, int N) {
    return 0.42f - 0.5f * cos(2.0f * M_PI * n / (N - 1)) + 0.08f * cos(4.0f * M_PI * n / (N - 1));
}

void FGCom_FrequencyOffsetProcessor::applyLowPassFilter(std::complex<float>* signal, size_t samples, float cutoff_freq, float sample_rate) {
    // Simple low-pass filter implementation
    float alpha = cutoff_freq / sample_rate;
    std::complex<float> prev = signal[0];
    
    for (size_t i = 1; i < samples; i++) {
        signal[i] = alpha * signal[i] + (1.0f - alpha) * prev;
        prev = signal[i];
    }
}

void FGCom_FrequencyOffsetProcessor::applyHighPassFilter(std::complex<float>* signal, size_t samples, float cutoff_freq, float sample_rate) {
    // Simple high-pass filter implementation
    float alpha = cutoff_freq / sample_rate;
    std::complex<float> prev = signal[0];
    
    for (size_t i = 1; i < samples; i++) {
        signal[i] = alpha * (signal[i] - prev) + signal[i-1];
        prev = signal[i];
    }
}

// Utility functions implementation
namespace FrequencyOffsetUtils {
    float hzToRadians(float frequency_hz, float sample_rate) {
        return 2.0f * M_PI * frequency_hz / sample_rate;
    }
    
    float radiansToHz(float radians, float sample_rate) {
        return radians * sample_rate / (2.0f * M_PI);
    }
    
    float normalizeFrequency(float frequency_hz, float sample_rate) {
        return frequency_hz / sample_rate;
    }
    
    float denormalizeFrequency(float normalized_freq, float sample_rate) {
        return normalized_freq * sample_rate;
    }
    
    std::complex<float> createComplexExponential(float frequency_hz, float time, float sample_rate) {
        float omega = hzToRadians(frequency_hz, sample_rate);
        return std::exp(std::complex<float>(0, omega * time));
    }
    
    std::complex<float> createComplexExponential(float frequency_hz, float time) {
        float omega = 2.0f * M_PI * frequency_hz;
        return std::exp(std::complex<float>(0, omega * time));
    }
    
    float getMagnitude(const std::complex<float>& complex_num) {
        return std::abs(complex_num);
    }
    
    float getPhase(const std::complex<float>& complex_num) {
        return std::arg(complex_num);
    }
    
    std::complex<float> fromMagnitudePhase(float magnitude, float phase) {
        return std::polar(magnitude, phase);
    }
    
    float calculateSNR(const float* signal, size_t samples) {
        // Simple SNR calculation
        float signal_power = 0.0f;
        float noise_power = 0.0f;
        
        for (size_t i = 0; i < samples; i++) {
            signal_power += signal[i] * signal[i];
        }
        signal_power /= samples;
        
        // Estimate noise power (simplified)
        noise_power = signal_power * 0.01f; // Assume 1% noise
        
        return 10.0f * log10(signal_power / noise_power);
    }
    
    float calculateTHD(const float* signal, size_t samples, float fundamental_freq, float sample_rate) {
        // Simplified THD calculation
        // In practice, this would require FFT analysis
        return 0.1f; // Placeholder
    }
    
    float calculateDynamicRange(const float* signal, size_t samples) {
        float max_val = *std::max_element(signal, signal + samples);
        float min_val = *std::min_element(signal, signal + samples);
        return 20.0f * log10(max_val / std::max(min_val, 1e-6f));
    }
    
    bool detectClipping(const float* signal, size_t samples, float threshold) {
        for (size_t i = 0; i < samples; i++) {
            if (std::abs(signal[i]) > threshold) {
                return true;
            }
        }
        return false;
    }
    
    float calculateDopplerShift(float relative_velocity_mps, float carrier_frequency_hz, float speed_of_light_mps) {
        return carrier_frequency_hz * relative_velocity_mps / speed_of_light_mps;
    }
    
    float calculateRelativisticDopplerShift(float relative_velocity_mps, float carrier_frequency_hz) {
        float beta = relative_velocity_mps / 299792458.0f;
        float gamma = 1.0f / sqrt(1.0f - beta * beta);
        return carrier_frequency_hz * gamma * (1.0f + beta);
    }
    
    float calculateAtmosphericRefractionCorrection(float elevation_angle_deg, float frequency_hz) {
        // Simplified atmospheric refraction correction
        float correction_factor = 1.0f + 0.0003f * sin(elevation_angle_deg * M_PI / 180.0f);
        return correction_factor;
    }
    
    std::complex<float> createLocalOscillator(float frequency_hz, float time, float sample_rate) {
        return createComplexExponential(frequency_hz, time, sample_rate);
    }
    
    void applyMixer(std::complex<float>* signal, const std::complex<float>* lo_signal, size_t samples) {
        for (size_t i = 0; i < samples; i++) {
            signal[i] *= lo_signal[i];
        }
    }
    
    float calculateImageRejection(float if_freq, float rf_freq, float lo_freq) {
        // Simplified image rejection calculation
        float image_freq = 2.0f * lo_freq - rf_freq;
        float rejection_ratio = std::abs(if_freq - image_freq) / if_freq;
        return 20.0f * log10(rejection_ratio);
    }
    
    float calculatePhaseNoiseVariance(float phase_noise_db_hz, float bandwidth_hz) {
        float phase_noise_linear = pow(10.0f, phase_noise_db_hz / 10.0f);
        return phase_noise_linear * bandwidth_hz;
    }
    
    float calculateSpectralCentroid(const float* signal, size_t samples, float sample_rate) {
        // Simplified spectral centroid calculation
        float centroid = 0.0f;
        float total_power = 0.0f;
        
        for (size_t i = 0; i < samples; i++) {
            float freq = static_cast<float>(i) * sample_rate / samples;
            float power = signal[i] * signal[i];
            centroid += freq * power;
            total_power += power;
        }
        
        return total_power > 0.0f ? centroid / total_power : 0.0f;
    }
    
    float calculateSpectralRolloff(const float* signal, size_t samples, float sample_rate, float rolloff_percent) {
        // Simplified spectral rolloff calculation
        float total_power = 0.0f;
        for (size_t i = 0; i < samples; i++) {
            total_power += signal[i] * signal[i];
        }
        
        float target_power = total_power * rolloff_percent;
        float cumulative_power = 0.0f;
        
        for (size_t i = 0; i < samples; i++) {
            cumulative_power += signal[i] * signal[i];
            if (cumulative_power >= target_power) {
                return static_cast<float>(i) * sample_rate / samples;
            }
        }
        
        return sample_rate / 2.0f;
    }
    
    float calculateSpectralFlux(const float* signal, size_t samples, float sample_rate) {
        // Simplified spectral flux calculation
        float flux = 0.0f;
        for (size_t i = 1; i < samples; i++) {
            float diff = signal[i] - signal[i-1];
            flux += diff * diff;
        }
        return flux / (samples - 1);
    }
    
    float calculateZeroCrossingRate(const float* signal, size_t samples) {
        int crossings = 0;
        for (size_t i = 1; i < samples; i++) {
            if ((signal[i] >= 0.0f) != (signal[i-1] >= 0.0f)) {
                crossings++;
            }
        }
        return static_cast<float>(crossings) / (samples - 1);
    }
    
    void generateWindowFunction(float* window, int size, const std::string& window_type) {
        if (window_type == "hann") {
            for (int i = 0; i < size; i++) {
                window[i] = 0.5f * (1.0f - cos(2.0f * M_PI * i / (size - 1)));
            }
        } else if (window_type == "hamming") {
            for (int i = 0; i < size; i++) {
                window[i] = 0.54f - 0.46f * cos(2.0f * M_PI * i / (size - 1));
            }
        } else if (window_type == "blackman") {
            for (int i = 0; i < size; i++) {
                window[i] = 0.42f - 0.5f * cos(2.0f * M_PI * i / (size - 1)) + 0.08f * cos(4.0f * M_PI * i / (size - 1));
            }
        } else {
            // Default to rectangular window
            std::fill(window, window + size, 1.0f);
        }
    }
    
    float calculateWindowGain(const float* window, int size) {
        float sum = 0.0f;
        for (int i = 0; i < size; i++) {
            sum += window[i];
        }
        return sum / size;
    }
    
    void applyWindowToSignal(float* signal, const float* window, int size) {
        for (int i = 0; i < size; i++) {
            signal[i] *= window[i];
        }
    }
    
    std::string getAvailableWindowTypes() {
        return "hann,hamming,blackman,rectangular";
    }
}
