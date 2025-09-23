/*
 * FGCom-mumble Frequency Offset Example
 * 
 * This example demonstrates how to use the advanced frequency offset processing system
 * for implementing the Donald Duck Effect and other frequency-based audio effects.
 */

#include "frequency_offset.h"
#include "audio.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <chrono>

// Example 1: Basic Donald Duck Effect
void exampleDonaldDuckEffect() {
    std::cout << "=== Donald Duck Effect Example ===" << std::endl;
    
    // Create a test audio signal (sine wave at 1000 Hz)
    const int sample_rate = 48000;
    const int duration_seconds = 2;
    const int sample_count = sample_rate * duration_seconds;
    const float frequency = 1000.0f; // 1 kHz test tone
    
    std::vector<float> audio_buffer(sample_count);
    
    // Generate test signal
    for (int i = 0; i < sample_count; i++) {
        float time = static_cast<float>(i) / sample_rate;
        audio_buffer[i] = 0.5f * sin(2.0f * M_PI * frequency * time);
    }
    
    // Apply Donald Duck effect (frequency shift up by 200 Hz)
    float donald_duck_offset = 200.0f;
    fgcom_audio_applyDonaldDuckEffect(0.25f, audio_buffer.data(), sample_count, 1, sample_rate);
    
    std::cout << "Applied Donald Duck effect with " << donald_duck_offset << " Hz offset" << std::endl;
    std::cout << "Original frequency: " << frequency << " Hz" << std::endl;
    std::cout << "New frequency: " << (frequency + donald_duck_offset) << " Hz" << std::endl;
}

// Example 2: Complex Exponential Method
void exampleComplexExponentialMethod() {
    std::cout << "\n=== Complex Exponential Method Example ===" << std::endl;
    
    // Get frequency offset processor instance
    auto& processor = FGCom_FrequencyOffsetProcessor::getInstance();
    
    // Configure processor
    FrequencyOffsetConfig config;
    config.enable_frequency_offset = true;
    config.enable_donald_duck_effect = true;
    config.sample_rate = 48000.0f;
    config.fft_size = 1024;
    config.enable_real_time_processing = true;
    processor.setConfig(config);
    
    // Create test signal
    const int sample_count = 1024;
    const float frequency = 2000.0f; // 2 kHz test tone
    std::vector<float> audio_buffer(sample_count);
    
    for (int i = 0; i < sample_count; i++) {
        float time = static_cast<float>(i) / config.sample_rate;
        audio_buffer[i] = 0.3f * sin(2.0f * M_PI * frequency * time);
    }
    
    // Apply frequency offset using complex exponential method
    float offset_hz = 500.0f;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    bool success = processor.applyComplexExponentialOffset(audio_buffer.data(), sample_count, offset_hz);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    if (success) {
        std::cout << "Complex exponential method applied successfully" << std::endl;
        std::cout << "Processing time: " << duration.count() << " microseconds" << std::endl;
        std::cout << "Frequency offset: " << offset_hz << " Hz" << std::endl;
    } else {
        std::cout << "Failed to apply complex exponential method" << std::endl;
    }
}

// Example 3: Doppler Shift Simulation
void exampleDopplerShift() {
    std::cout << "\n=== Doppler Shift Example ===" << std::endl;
    
    auto& processor = FGCom_FrequencyOffsetProcessor::getInstance();
    
    // Set up Doppler shift parameters
    DopplerShiftParams doppler_params;
    doppler_params.relative_velocity_mps = 100.0f; // 100 m/s relative velocity
    doppler_params.carrier_frequency_hz = 14.230e6f; // 14.230 MHz (20m amateur band)
    doppler_params.speed_of_light_mps = 299792458.0f;
    doppler_params.enable_relativistic_correction = true;
    doppler_params.atmospheric_refraction_factor = 1.0003f;
    
    processor.setDopplerParams(doppler_params);
    
    // Calculate expected Doppler shift
    float expected_shift = FrequencyOffsetUtils::calculateDopplerShift(
        doppler_params.relative_velocity_mps,
        doppler_params.carrier_frequency_hz,
        doppler_params.speed_of_light_mps
    );
    
    std::cout << "Doppler shift parameters:" << std::endl;
    std::cout << "  Relative velocity: " << doppler_params.relative_velocity_mps << " m/s" << std::endl;
    std::cout << "  Carrier frequency: " << doppler_params.carrier_frequency_hz / 1e6f << " MHz" << std::endl;
    std::cout << "  Expected Doppler shift: " << expected_shift << " Hz" << std::endl;
    
    // Create test signal
    const int sample_count = 2048;
    std::vector<float> audio_buffer(sample_count);
    
    for (int i = 0; i < sample_count; i++) {
        float time = static_cast<float>(i) / 48000.0f;
        audio_buffer[i] = 0.2f * sin(2.0f * M_PI * 1000.0f * time); // 1 kHz audio
    }
    
    // Apply Doppler shift
    bool success = processor.applyDopplerShift(audio_buffer.data(), sample_count, doppler_params);
    
    if (success) {
        std::cout << "Doppler shift applied successfully" << std::endl;
    } else {
        std::cout << "Failed to apply Doppler shift" << std::endl;
    }
}

// Example 4: Heterodyne Mixing
void exampleHeterodyneMixing() {
    std::cout << "\n=== Heterodyne Mixing Example ===" << std::endl;
    
    auto& processor = FGCom_FrequencyOffsetProcessor::getInstance();
    
    // Set up heterodyne mixing parameters
    HeterodyneMixingParams heterodyne_params;
    heterodyne_params.local_oscillator_freq_hz = 10.0e6f; // 10 MHz LO
    heterodyne_params.intermediate_freq_hz = 455000.0f; // 455 kHz IF
    heterodyne_params.enable_image_rejection = true;
    heterodyne_params.image_rejection_db = 40.0f;
    heterodyne_params.enable_phase_noise = true;
    heterodyne_params.phase_noise_db_hz = -80.0f;
    
    processor.setHeterodyneParams(heterodyne_params);
    
    std::cout << "Heterodyne mixing parameters:" << std::endl;
    std::cout << "  Local oscillator: " << heterodyne_params.local_oscillator_freq_hz / 1e6f << " MHz" << std::endl;
    std::cout << "  Intermediate frequency: " << heterodyne_params.intermediate_freq_hz / 1e3f << " kHz" << std::endl;
    std::cout << "  Image rejection: " << heterodyne_params.image_rejection_db << " dB" << std::endl;
    std::cout << "  Phase noise: " << heterodyne_params.phase_noise_db_hz << " dB/Hz" << std::endl;
    
    // Create test signal
    const int sample_count = 1024;
    std::vector<float> audio_buffer(sample_count);
    
    for (int i = 0; i < sample_count; i++) {
        float time = static_cast<float>(i) / 48000.0f;
        audio_buffer[i] = 0.3f * sin(2.0f * M_PI * 1000.0f * time); // 1 kHz audio
    }
    
    // Apply heterodyne mixing
    bool success = processor.applyHeterodyneMixing(audio_buffer.data(), sample_count, heterodyne_params);
    
    if (success) {
        std::cout << "Heterodyne mixing applied successfully" << std::endl;
    } else {
        std::cout << "Failed to apply heterodyne mixing" << std::endl;
    }
}

// Example 5: Real-time Processing
void exampleRealTimeProcessing() {
    std::cout << "\n=== Real-time Processing Example ===" << std::endl;
    
    auto& processor = FGCom_FrequencyOffsetProcessor::getInstance();
    
    // Start real-time processing
    if (processor.startRealTimeProcessing()) {
        std::cout << "Real-time processing started" << std::endl;
        
        // Simulate real-time audio processing
        const int frame_size = 512;
        const int num_frames = 10;
        
        for (int frame = 0; frame < num_frames; frame++) {
            std::vector<float> audio_frame(frame_size);
            
            // Generate test frame
            for (int i = 0; i < frame_size; i++) {
                float time = static_cast<float>(i) / 48000.0f;
                audio_frame[i] = 0.2f * sin(2.0f * M_PI * 1000.0f * time);
            }
            
            // Apply frequency offset with smooth changes
            float offset = 100.0f + 50.0f * sin(2.0f * M_PI * frame / num_frames);
            processor.setTargetOffset(offset);
            processor.updateOffsetSmoothly(offset);
            
            // Process frame
            bool success = processor.applyRealTimeOffset(audio_frame.data(), frame_size, offset);
            
            if (success) {
                std::cout << "Frame " << frame << " processed with offset " << offset << " Hz" << std::endl;
            }
            
            // Simulate real-time delay
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        // Stop real-time processing
        processor.stopRealTimeProcessing();
        std::cout << "Real-time processing stopped" << std::endl;
    } else {
        std::cout << "Failed to start real-time processing" << std::endl;
    }
}

// Example 6: Performance Benchmarking
void examplePerformanceBenchmark() {
    std::cout << "\n=== Performance Benchmark Example ===" << std::endl;
    
    auto& processor = FGCom_FrequencyOffsetProcessor::getInstance();
    
    // Test different processing methods
    const int sample_count = 4096;
    const int num_iterations = 100;
    std::vector<float> audio_buffer(sample_count);
    
    // Generate test signal
    for (int i = 0; i < sample_count; i++) {
        float time = static_cast<float>(i) / 48000.0f;
        audio_buffer[i] = 0.3f * sin(2.0f * M_PI * 1000.0f * time);
    }
    
    // Benchmark complex exponential method
    auto start_time = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_iterations; i++) {
        processor.applyComplexExponentialOffset(audio_buffer.data(), sample_count, 200.0f);
    }
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    std::cout << "Complex exponential method:" << std::endl;
    std::cout << "  Total time: " << duration.count() << " microseconds" << std::endl;
    std::cout << "  Average time per call: " << duration.count() / num_iterations << " microseconds" << std::endl;
    std::cout << "  Samples per second: " << (sample_count * num_iterations * 1000000) / duration.count() << std::endl;
    
    // Get processing statistics
    FrequencyOffsetStats stats = processor.getStats();
    std::cout << "\nProcessing statistics:" << std::endl;
    std::cout << "  Total offsets applied: " << stats.total_offsets_applied << std::endl;
    std::cout << "  Average processing time: " << stats.processing_time_ms << " ms" << std::endl;
    std::cout << "  Peak offset used: " << stats.peak_offset_hz << " Hz" << std::endl;
    std::cout << "  CPU usage: " << stats.cpu_usage_percent << "%" << std::endl;
}

// Example 7: Configuration Management
void exampleConfigurationManagement() {
    std::cout << "\n=== Configuration Management Example ===" << std::endl;
    
    auto& processor = FGCom_FrequencyOffsetProcessor::getInstance();
    
    // Load configuration from file
    if (processor.loadConfigFromFile("frequency_offset.conf")) {
        std::cout << "Configuration loaded from file" << std::endl;
    } else {
        std::cout << "Failed to load configuration, using defaults" << std::endl;
    }
    
    // Get current configuration
    FrequencyOffsetConfig config = processor.getConfig();
    std::cout << "Current configuration:" << std::endl;
    std::cout << "  Frequency offset enabled: " << (config.enable_frequency_offset ? "yes" : "no") << std::endl;
    std::cout << "  Donald Duck effect enabled: " << (config.enable_donald_duck_effect ? "yes" : "no") << std::endl;
    std::cout << "  Sample rate: " << config.sample_rate << " Hz" << std::endl;
    std::cout << "  FFT size: " << config.fft_size << std::endl;
    std::cout << "  Max offset: " << config.max_offset_hz << " Hz" << std::endl;
    std::cout << "  Min offset: " << config.min_offset_hz << " Hz" << std::endl;
    
    // Modify configuration
    config.enable_donald_duck_effect = true;
    config.max_offset_hz = 1500.0f;
    config.offset_smoothing_factor = 0.2f;
    processor.setConfig(config);
    
    std::cout << "Configuration updated" << std::endl;
    
    // Save configuration to file
    if (processor.saveConfigToFile("frequency_offset_modified.conf")) {
        std::cout << "Modified configuration saved to file" << std::endl;
    } else {
        std::cout << "Failed to save configuration" << std::endl;
    }
}

// Main example function
int main() {
    std::cout << "FGCom-mumble Frequency Offset Processing Examples" << std::endl;
    std::cout << "=================================================" << std::endl;
    
    try {
        // Run all examples
        exampleDonaldDuckEffect();
        exampleComplexExponentialMethod();
        exampleDopplerShift();
        exampleHeterodyneMixing();
        exampleRealTimeProcessing();
        examplePerformanceBenchmark();
        exampleConfigurationManagement();
        
        std::cout << "\nAll examples completed successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error running examples: " << e.what() << std::endl;
        return 1;
    }
    
    // Clean up
    FGCom_FrequencyOffsetProcessor::destroyInstance();
    
    return 0;
}
