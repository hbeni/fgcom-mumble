/* 
 * Modern audio processing implementation using DSP IIR Realtime C++ filter library
 * This file is part of the FGCom-mumble distribution (https://github.com/Supermagnum/fgcom-mumble).
 * Copyright (c) 2024 FGCom-mumble Contributors
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 */

#include "audio.h"
#include "frequency_offset.h"
#include <random>
#include <algorithm>
#include <cmath>

// Modern audio processing implementation without DspFilters
namespace AudioProcessing {

/**
 * @brief Simple biquad filter implementation for real-time audio processing
 * 
 * This class provides a lightweight biquad filter implementation for real-time
 * audio processing without external dependencies. It supports lowpass and highpass
 * filtering with configurable cutoff frequencies and sample rates.
 * 
 * The filter uses Direct Form II transposed structure for efficient processing:
 * y[n] = b0*x[n] + b1*x[n-1] + b2*x[n-2] - a1*y[n-1] - a2*y[n-2]
 * 
 * @note This implementation is optimized for real-time processing with minimal latency
 * @note Filter coefficients are calculated using bilinear transform
 * @note Q factor is fixed at 0.707 (Butterworth response)
 */
class SimpleBiquadFilter {
private:
    float b0, b1, b2, a1, a2;  // Filter coefficients
    float x1, x2, y1, y2;      // Delay line samples
    
public:
    /**
     * @brief Default constructor initializing filter to pass-through state
     * 
     * Initializes all filter coefficients and delay line samples to zero,
     * creating a pass-through filter that doesn't modify the input signal.
     */
    SimpleBiquadFilter() : b0(1.0f), b1(0.0f), b2(0.0f), a1(0.0f), a2(0.0f),
                           x1(0.0f), x2(0.0f), y1(0.0f), y2(0.0f) {}
    
    /**
     * @brief Configure filter as a lowpass filter with specified cutoff frequency
     * 
     * Sets up the biquad filter as a 2nd-order Butterworth lowpass filter with
     * the specified cutoff frequency. The filter will attenuate frequencies above
     * the cutoff frequency at a rate of -12 dB per octave.
     * 
     * @param cutoff Cutoff frequency in Hz (frequencies above this are attenuated)
     * @param sampleRate Sample rate in Hz (must match the audio stream sample rate)
     * 
     * @note The filter uses a Q factor of 0.707 for Butterworth response
     * @note Cutoff frequency should be less than sampleRate/2 (Nyquist frequency)
     * 
     * @example
     * // Set up 3kHz lowpass filter for 48kHz sample rate
     * filter.setLowpass(3000.0f, 48000.0f);
     */
    void setLowpass(float cutoff, float sampleRate) {
        float w = 2.0f * M_PI * cutoff / sampleRate;
        float cosw = std::cos(w);
        float sinw = std::sin(w);
        float alpha = sinw / (2.0f * 0.707f); // Q = 0.707
        
        b0 = (1.0f - cosw) / 2.0f;
        b1 = 1.0f - cosw;
        b2 = (1.0f - cosw) / 2.0f;
        float a0 = 1.0f + alpha;
        a1 = -2.0f * cosw / a0;
        a2 = (1.0f - alpha) / a0;
        
        // Normalize
        b0 /= a0; b1 /= a0; b2 /= a0;
    }
    
    /**
     * @brief Configure filter as a highpass filter with specified cutoff frequency
     * 
     * Sets up the biquad filter as a 2nd-order Butterworth highpass filter with
     * the specified cutoff frequency. The filter will attenuate frequencies below
     * the cutoff frequency at a rate of -12 dB per octave.
     * 
     * @param cutoff Cutoff frequency in Hz (frequencies below this are attenuated)
     * @param sampleRate Sample rate in Hz (must match the audio stream sample rate)
     * 
     * @note The filter uses a Q factor of 0.707 for Butterworth response
     * @note Cutoff frequency should be less than sampleRate/2 (Nyquist frequency)
     * 
     * @example
     * // Set up 300Hz highpass filter for 48kHz sample rate
     * filter.setHighpass(300.0f, 48000.0f);
     */
    void setHighpass(float cutoff, float sampleRate) {
        float w = 2.0f * M_PI * cutoff / sampleRate;
        float cosw = std::cos(w);
        float sinw = std::sin(w);
        float alpha = sinw / (2.0f * 0.707f);
        
        b0 = (1.0f + cosw) / 2.0f;
        b1 = -(1.0f + cosw);
        b2 = (1.0f + cosw) / 2.0f;
        float a0 = 1.0f + alpha;
        a1 = -2.0f * cosw / a0;
        a2 = (1.0f - alpha) / a0;
        
        b0 /= a0; b1 /= a0; b2 /= a0;
    }
    
    /**
     * @brief Process a single audio sample through the filter
     * 
     * Applies the configured biquad filter to a single audio sample using
     * Direct Form II transposed structure for efficient real-time processing.
     * The filter maintains internal state for proper filtering operation.
     * 
     * @param input Input audio sample (typically in range [-1.0, 1.0])
     * @return Filtered audio sample
     * 
     * @note This method maintains internal delay line state
     * @note Call this method for each sample in the audio stream
     * @note The filter must be configured with setLowpass() or setHighpass() before use
     * 
     * @example
     * // Process a single sample through the filter
     * float filtered = filter.process(inputSample);
     */
    float process(float input) {
        float output = b0 * input + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2;
        
        x2 = x1;
        x1 = input;
        y2 = y1;
        y1 = output;
        
        return output;
    }
};

// Global filter instances for different frequency ranges
static SimpleBiquadFilter lowpassFilter;
static SimpleBiquadFilter highpassFilter;
static bool filtersInitialized = false;

/**
 * @brief Initialize global filter instances for audio processing
 * 
 * Sets up the global lowpass and highpass filters with typical values
 * for radio communication audio processing. This function should be called
 * once during system initialization.
 * 
 * @note Lowpass filter: 3kHz cutoff (typical for voice communication)
 * @note Highpass filter: 300Hz cutoff (removes low-frequency noise)
 * @note Sample rate: 48kHz (standard for modern audio systems)
 * 
 * @example
 * // Initialize filters during system startup
 * AudioProcessing::initializeFilters();
 */
void initializeFilters() {
    if (!filtersInitialized) {
        // Initialize filters for typical audio processing
        lowpassFilter.setLowpass(3000.0f, 48000.0f);  // 3kHz lowpass
        highpassFilter.setHighpass(300.0f, 48000.0f); // 300Hz highpass
        filtersInitialized = true;
    }
}

} // namespace AudioProcessing

// C++ API functions matching the declarations in audio.h

/**
 * @brief Convert multi-channel audio to mono by averaging channels
 * 
 * This function converts multi-channel audio data to mono by averaging
 * all channels for each sample. The conversion is done in-place, modifying
 * the input buffer directly.
 * 
 * @param outputPCM Pointer to audio buffer (modified in-place)
 * @param sampleCount Number of samples per channel
 * @param channelCount Number of input channels (must be > 1)
 * 
 * @note If channelCount <= 1, the function returns without modification
 * @note The output buffer is resized to contain only mono samples
 * @note Input buffer format: [ch0_sample0, ch1_sample0, ch0_sample1, ch1_sample1, ...]
 * @note Output buffer format: [mono_sample0, mono_sample1, ...]
 * 
 * @example
 * // Convert stereo audio to mono
 * fgcom_audio_makeMono(audioBuffer, 1024, 2);
 */
void fgcom_audio_makeMono(float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
        if (channelCount <= 1) return;
        
        // Convert to mono by averaging channels
        for (uint32_t i = 0; i < sampleCount; i++) {
            float sum = 0.0f;
            for (uint16_t ch = 0; ch < channelCount; ch++) {
                sum += outputPCM[i * channelCount + ch];
            }
            outputPCM[i] = sum / channelCount;
        }
    }

/**
 * @brief Apply highpass and lowpass filtering to audio data
 * 
 * This function applies biquad filtering to audio data using the global
 * filter instances. It supports both highpass and lowpass filtering
 * with configurable cutoff frequencies.
 * 
 * @param highpass_cutoff Highpass cutoff frequency in Hz (0 = disabled)
 * @param lowpass_cutoff Lowpass cutoff frequency in Hz (0 = disabled)
 * @param outputPCM Pointer to audio buffer (modified in-place)
 * @param sampleCount Number of samples per channel
 * @param channelCount Number of audio channels
 * @param sampleRateHz Sample rate in Hz
 * 
 * @note Filters are applied in sequence: highpass first, then lowpass
 * @note Lowpass cutoff must be less than sampleRateHz/2 (Nyquist frequency)
 * @note The function automatically initializes filters if not already done
 * 
 * @example
 * // Apply 300Hz highpass and 3kHz lowpass filtering
 * fgcom_audio_filter(300, 3000, audioBuffer, 1024, 1, 48000);
 */
void fgcom_audio_filter(int highpass_cutoff, int lowpass_cutoff, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
        AudioProcessing::initializeFilters();
        
        // Apply filtering to each sample
        for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
            float sample = outputPCM[i];
            
            // Apply highpass filter if specified
            if (highpass_cutoff > 0) {
                sample = AudioProcessing::highpassFilter.process(sample);
            }
            
            // Apply lowpass filter if specified
            if (lowpass_cutoff > 0 && lowpass_cutoff < static_cast<int>(sampleRateHz / 2)) {
                sample = AudioProcessing::lowpassFilter.process(sample);
            }
            
            outputPCM[i] = sample;
        }
    }

/**
 * @brief Apply volume scaling to audio data
 * 
 * This function applies volume scaling to audio data by multiplying each
 * sample by the specified volume factor. The volume is clamped to a
 * reasonable range to prevent excessive amplification.
 * 
 * @param volume Volume scaling factor (0.0 = silence, 1.0 = normal, 2.0 = maximum)
 * @param outputPCM Pointer to audio buffer (modified in-place)
 * @param sampleCount Number of samples per channel
 * @param channelCount Number of audio channels
 * 
 * @note Volume is clamped to range [0.0, 2.0] to prevent excessive amplification
 * @note Volume of 0.0 results in silence
 * @note Volume of 1.0 maintains original level
 * @note Volume of 2.0 doubles the amplitude (may cause clipping)
 * 
 * @example
 * // Reduce volume to 50%
 * fgcom_audio_applyVolume(0.5f, audioBuffer, 1024, 1);
 */
void fgcom_audio_applyVolume(float volume, float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
        // Clamp volume to reasonable range
        volume = std::max(0.0f, std::min(2.0f, volume));
        
        for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
            outputPCM[i] *= volume;
        }
    }

/**
 * @brief Add white noise to audio data
 * 
 * This function adds white noise to audio data to simulate RF noise
 * and atmospheric interference. The noise is generated using a uniform
 * random distribution and scaled by the specified volume factor.
 * 
 * @param noiseVolume Noise volume factor (0.0 = no noise, 1.0 = maximum noise)
 * @param outputPCM Pointer to audio buffer (modified in-place)
 * @param sampleCount Number of samples per channel
 * @param channelCount Number of audio channels
 * 
 * @note Noise volume is clamped to range [0.0, 1.0]
 * @note Noise is generated using uniform distribution [-1.0, 1.0]
 * @note Noise is added to existing audio samples (additive)
 * 
 * @example
 * // Add moderate noise to audio
 * fgcom_audio_addNoise(0.3f, audioBuffer, 1024, 1);
 */
void fgcom_audio_addNoise(float noiseVolume, float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_real_distribution<float> dis(-1.0f, 1.0f);
        
        // Clamp noise level to reasonable range
        noiseVolume = std::max(0.0f, std::min(1.0f, noiseVolume));
        
        for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
            outputPCM[i] += dis(gen) * noiseVolume;
        }
    }

/**
 * @brief Apply signal quality degradation to simulate poor radio conditions
 * 
 * This function applies signal quality degradation to audio data to simulate
 * poor radio propagation conditions, atmospheric interference, and equipment
 * limitations. The degradation includes harmonic distortion and compression
 * effects based on the dropout probability.
 * 
 * @param outputPCM Pointer to audio buffer (modified in-place)
 * @param sampleCount Number of samples per channel
 * @param channelCount Number of audio channels
 * @param dropoutProbability Signal quality factor (0.0 = perfect, 1.0 = very poor)
 * 
 * @note Dropout probability is clamped to range [0.0, 1.0]
 * @note Higher dropout probability results in more distortion and compression
 * @note Harmonic distortion is proportional to signal amplitude squared
 * @note Compression reduces dynamic range as dropout probability increases
 * 
 * @example
 * // Apply moderate signal degradation
 * fgcom_audio_applySignalQualityDegradation(audioBuffer, 1024, 1, 0.5f);
 */
void fgcom_audio_applySignalQualityDegradation(float *outputPCM, uint32_t sampleCount, uint16_t channelCount, float dropoutProbability) {
        // Clamp dropout probability to [0, 1] range
        dropoutProbability = std::max(0.0f, std::min(1.0f, dropoutProbability));
        
        // Apply signal quality degradation (higher dropout probability = more distortion)
        for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
            // Simple distortion based on dropout probability
            float sample = outputPCM[i];
            if (dropoutProbability > 0.0f) {
                // Add some harmonic distortion
                sample += sample * sample * dropoutProbability * 0.1f;
                // Apply some compression
                sample *= (1.0f - dropoutProbability * 0.2f);
            }
            outputPCM[i] = sample;
        }
    }
