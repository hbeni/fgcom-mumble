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

// Simple biquad filter implementation
class SimpleBiquadFilter {
private:
    float b0, b1, b2, a1, a2;
    float x1, x2, y1, y2;
    
public:
    SimpleBiquadFilter() : b0(1.0f), b1(0.0f), b2(0.0f), a1(0.0f), a2(0.0f),
                           x1(0.0f), x2(0.0f), y1(0.0f), y2(0.0f) {}
    
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
            if (lowpass_cutoff > 0 && lowpass_cutoff < sampleRateHz / 2) {
                sample = AudioProcessing::lowpassFilter.process(sample);
            }
            
            outputPCM[i] = sample;
        }
    }

void fgcom_audio_applyVolume(float volume, float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
        // Clamp volume to reasonable range
        volume = std::max(0.0f, std::min(2.0f, volume));
        
        for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
            outputPCM[i] *= volume;
        }
    }

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
