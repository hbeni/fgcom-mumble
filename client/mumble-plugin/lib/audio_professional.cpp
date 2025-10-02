/* 
 * Professional Audio Processing Implementation for FGCom-mumble
 * This file is part of the FGCom-mumble distribution (https://github.com/Supermagnum/fgcom-mumble).
 * Copyright (c) 2024 FGCom-mumble Contributors
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 */

#include "audio_professional.h"
#include "audio.h"
#include <algorithm>
#include <cmath>
#include <random>
#include <chrono>

namespace FGComAudio {

// Global professional audio processor instances
static std::unique_ptr<ProfessionalAudioEngine> g_audioProcessor;
static std::unique_ptr<VHFAudioProcessor> g_vhfProcessor;
static std::unique_ptr<HFAudioProcessor> g_hfProcessor;
static std::unique_ptr<AmateurRadioProcessor> g_amateurProcessor;
static std::unique_ptr<WebRTCAudioProcessor> g_webrtcProcessor;
static std::unique_ptr<SovietVHFProcessor> g_sovietProcessor;

// IIR1Filter Implementation - optimized for radio bandpass filtering
IIR1Filter::IIR1Filter() : a0(1), a1(0), b1(0), x1(0), y1(0), isHighPass(false) {}

void IIR1Filter::setLowPass(float cutoff, float sampleRate) {
    isHighPass = false;
    calculateCoefficients(cutoff, sampleRate, false);
}

void IIR1Filter::setHighPass(float cutoff, float sampleRate) {
    isHighPass = true;
    calculateCoefficients(cutoff, sampleRate, true);
}

void IIR1Filter::setBandPass(float lowCutoff, float highCutoff, float sampleRate) {
    // For bandpass, we'll use a combination of high-pass and low-pass
    // This is more efficient than a single IIR1 filter
    isHighPass = false;
    calculateCoefficients(lowCutoff, sampleRate, true);  // High-pass at low cutoff
}

float IIR1Filter::process(float input) {
    float output = a0 * input + a1 * x1 - b1 * y1;
    x1 = input;
    y1 = output;
    return output;
}

void IIR1Filter::reset() {
    x1 = y1 = 0.0f;
}

void IIR1Filter::calculateCoefficients(float cutoff, float sampleRate, bool isHighPass) {
    float omega = 2.0f * M_PI * cutoff / sampleRate;
    float cosw = cosf(omega);
    float sinw = sinf(omega);
    float alpha = sinw / (2.0f * 0.707f); // Q = 0.707 for Butterworth response
    
    if (isHighPass) {
        // High-pass filter coefficients
        a0 = (1.0f + cosw) / 2.0f;
        a1 = -(1.0f + cosw);
        b1 = cosw;
    } else {
        // Low-pass filter coefficients
        a0 = (1.0f - cosw) / 2.0f;
        a1 = 1.0f - cosw;
        b1 = cosw;
    }
}

// BiquadFilter Implementation
BiquadFilter::BiquadFilter() : a0(1), a1(0), a2(0), b1(0), b2(0), x1(0), x2(0), y1(0), y2(0) {}

void BiquadFilter::setLowPass(float cutoff, float sampleRate, float Q) {
    float w = 2.0f * M_PI * cutoff / sampleRate;
    float cosw = cosf(w);
    float sinw = sinf(w);
    float alpha = sinw / (2.0f * Q);
    
    float b0 = (1.0f - cosw) / 2.0f;
    float b1 = 1.0f - cosw;
    float b2 = (1.0f - cosw) / 2.0f;
    float a0_val = 1.0f + alpha;
    float a1_val = -2.0f * cosw;
    float a2_val = 1.0f - alpha;
    
    calculateCoefficients(b0, b1, b2, a0_val, a1_val, a2_val);
}

void BiquadFilter::setHighPass(float cutoff, float sampleRate, float Q) {
    float w = 2.0f * M_PI * cutoff / sampleRate;
    float cosw = cosf(w);
    float sinw = sinf(w);
    float alpha = sinw / (2.0f * Q);
    
    float b0 = (1.0f + cosw) / 2.0f;
    float b1 = -(1.0f + cosw);
    float b2 = (1.0f + cosw) / 2.0f;
    float a0_val = 1.0f + alpha;
    float a1_val = -2.0f * cosw;
    float a2_val = 1.0f - alpha;
    
    calculateCoefficients(b0, b1, b2, a0_val, a1_val, a2_val);
}

void BiquadFilter::setBandPass(float lowCutoff, float highCutoff, float sampleRate, float Q) {
    float centerFreq = sqrtf(lowCutoff * highCutoff);
    float bandwidth = highCutoff - lowCutoff;
    float w = 2.0f * M_PI * centerFreq / sampleRate;
    float cosw = cosf(w);
    float sinw = sinf(w);
    float alpha = sinw * sinhf(logf(2.0f) / 2.0f * bandwidth * w / sinw);
    
    float b0 = sinw / 2.0f;
    float b1 = 0.0f;
    float b2 = -sinw / 2.0f;
    float a0_val = 1.0f + alpha;
    float a1_val = -2.0f * cosw;
    float a2_val = 1.0f - alpha;
    
    calculateCoefficients(b0, b1, b2, a0_val, a1_val, a2_val);
}

void BiquadFilter::setNotch(float frequency, float sampleRate, float Q) {
    float w = 2.0f * M_PI * frequency / sampleRate;
    float cosw = cosf(w);
    float sinw = sinf(w);
    float alpha = sinw / (2.0f * Q);
    
    float b0 = 1.0f;
    float b1 = -2.0f * cosw;
    float b2 = 1.0f;
    float a0_val = 1.0f + alpha;
    float a1_val = -2.0f * cosw;
    float a2_val = 1.0f - alpha;
    
    calculateCoefficients(b0, b1, b2, a0_val, a1_val, a2_val);
}

void BiquadFilter::setAllPass(float frequency, float sampleRate, float Q) {
    float w = 2.0f * M_PI * frequency / sampleRate;
    float cosw = cosf(w);
    float sinw = sinf(w);
    float alpha = sinw / (2.0f * Q);
    
    float b0 = 1.0f - alpha;
    float b1 = -2.0f * cosw;
    float b2 = 1.0f + alpha;
    float a0_val = 1.0f + alpha;
    float a1_val = -2.0f * cosw;
    float a2_val = 1.0f - alpha;
    
    calculateCoefficients(b0, b1, b2, a0_val, a1_val, a2_val);
}

float BiquadFilter::process(float input) {
    float output = a0 * input + a1 * x1 + a2 * x2 - b1 * y1 - b2 * y2;
    
    x2 = x1;
    x1 = input;
    y2 = y1;
    y1 = output;
    
    return output;
}

void BiquadFilter::reset() {
    x1 = x2 = y1 = y2 = 0.0f;
}

void BiquadFilter::calculateCoefficients(float b0, float b1, float b2, float a0, float a1, float a2) {
    this->a0 = b0 / a0;
    this->a1 = b1 / a0;
    this->a2 = b2 / a0;
    this->b1 = a1 / a0;
    this->b2 = a2 / a0;
}

// ReverbProcessor Implementation
FGComAudio::ProfessionalAudioEngine::ReverbProcessor::ReverbProcessor() : currentSample(0), roomSize(0.3f), dampingAmount(0.5f), 
                                   wetLevel(0.3f), dryLevel(0.7f) {
    delayTimes = {347, 113, 37, 59, 73, 89, 97, 101};
    delayLines[0].resize(347);
    delayLines[1].resize(113);
    delayLines[2].resize(37);
    delayLines[3].resize(59);
    delayLines[4].resize(73);
    delayLines[5].resize(89);
    delayLines[6].resize(97);
    delayLines[7].resize(101);
    
    feedback.resize(8);
    damping.resize(8);
    for (int i = 0; i < 8; ++i) {
        feedback[i] = 0.4f + (i * 0.1f);
        damping[i] = 0.5f;
    }
}

void FGComAudio::ProfessionalAudioEngine::ReverbProcessor::setParameters(float roomSize, float damping, float wetLevel, float dryLevel) {
    this->roomSize = roomSize;
    this->dampingAmount = damping;
    this->wetLevel = wetLevel;
    this->dryLevel = dryLevel;
}

void FGComAudio::ProfessionalAudioEngine::ReverbProcessor::process(float* samples, uint32_t sampleCount, uint16_t channelCount) {
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        float input = samples[i];
        float output = 0.0f;
        
        // Process through delay lines
        for (int j = 0; j < 8; ++j) {
            int delayIndex = currentSample % delayTimes[j];
            float delayed = delayLines[j][delayIndex];
            delayLines[j][delayIndex] = input + delayed * feedback[j] * (1.0f - damping[j]);
            output += delayed * (1.0f - damping[j]);
        }
        
        // Apply room size and damping
        output *= roomSize;
        for (int j = 0; j < 8; ++j) {
            damping[j] = dampingAmount;
        }
        
        // Mix wet and dry
        samples[i] = input * dryLevel + output * wetLevel;
        currentSample++;
    }
}

void FGComAudio::ProfessionalAudioEngine::ReverbProcessor::reset() {
    currentSample = 0;
    for (int i = 0; i < 8; ++i) {
        std::fill(delayLines[i].begin(), delayLines[i].end(), 0.0f);
    }
}

// ChorusProcessor Implementation
FGComAudio::ProfessionalAudioEngine::ChorusProcessor::ChorusProcessor() : lfoPhase(0.0f), rate(0.5f), depth(0.1f), 
                                   feedback(0.0f), mix(0.5f), delayLineSize(1024), currentSample(0) {
    delayLine.resize(delayLineSize);
}

void FGComAudio::ProfessionalAudioEngine::ChorusProcessor::setParameters(float rate, float depth, float feedback, float mix) {
    this->rate = rate;
    this->depth = depth;
    this->feedback = feedback;
    this->mix = mix;
}

void FGComAudio::ProfessionalAudioEngine::ChorusProcessor::process(float* samples, uint32_t sampleCount, uint16_t channelCount) {
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        float input = samples[i];
        
        // Generate LFO
        float lfo = sinf(lfoPhase * 2.0f * M_PI);
        lfoPhase += rate / 44100.0f; // Assuming 44.1kHz
        if (lfoPhase >= 1.0f) lfoPhase -= 1.0f;
        
        // Calculate delay time
        float delayTime = 0.005f + depth * (lfo + 1.0f) * 0.5f; // 5-15ms delay
        int delaySamples = static_cast<int>(delayTime * 44100.0f);
        delaySamples = std::max(1, std::min(delaySamples, delayLineSize - 1));
        
        // Get delayed sample
        int delayIndex = (currentSample - delaySamples + delayLineSize) % delayLineSize;
        float delayed = delayLine[delayIndex];
        
        // Update delay line
        delayLine[currentSample % delayLineSize] = input + delayed * feedback;
        
        // Mix original and delayed
        samples[i] = input * (1.0f - mix) + delayed * mix;
        currentSample++;
    }
}

void FGComAudio::ProfessionalAudioEngine::ChorusProcessor::reset() {
    lfoPhase = 0.0f;
    currentSample = 0;
    std::fill(delayLine.begin(), delayLine.end(), 0.0f);
}

// CompressorProcessor Implementation
FGComAudio::ProfessionalAudioEngine::CompressorProcessor::CompressorProcessor() : threshold(-20.0f), ratio(3.0f), 
                                           attack(0.003f), release(0.1f), envelope(0.0f), gain(1.0f) {}

void FGComAudio::ProfessionalAudioEngine::CompressorProcessor::setParameters(float threshold, float ratio, float attack, float release) {
    this->threshold = threshold;
    this->ratio = ratio;
    this->attack = attack;
    this->release = release;
}

void FGComAudio::ProfessionalAudioEngine::CompressorProcessor::process(float* samples, uint32_t sampleCount, uint16_t channelCount) {
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        float input = samples[i];
        float inputDb = 20.0f * log10f(fabsf(input) + 1e-10f);
        
        if (inputDb > threshold) {
            float overThreshold = inputDb - threshold;
            float compressedDb = threshold + overThreshold / ratio;
            float targetGain = powf(10.0f, (compressedDb - inputDb) / 20.0f);
            
            if (targetGain < gain) {
                gain += (targetGain - gain) * attack;
            } else {
                gain += (targetGain - gain) * release;
            }
        } else {
            gain += (1.0f - gain) * release;
        }
        
        samples[i] *= gain;
    }
}

void FGComAudio::ProfessionalAudioEngine::CompressorProcessor::reset() {
    envelope = 0.0f;
    gain = 1.0f;
}

// NoiseGateProcessor Implementation
FGComAudio::ProfessionalAudioEngine::NoiseGateProcessor::NoiseGateProcessor() : threshold(-40.0f), attack(0.001f), 
                                         release(0.1f), envelope(0.0f), gain(1.0f) {}

void FGComAudio::ProfessionalAudioEngine::NoiseGateProcessor::setParameters(float threshold, float attack, float release) {
    this->threshold = threshold;
    this->attack = attack;
    this->release = release;
}

void FGComAudio::ProfessionalAudioEngine::NoiseGateProcessor::process(float* samples, uint32_t sampleCount, uint16_t channelCount) {
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        float input = samples[i];
        float inputDb = 20.0f * log10f(fabsf(input) + 1e-10f);
        
        if (inputDb > threshold) {
            gain += (1.0f - gain) * attack;
        } else {
            gain += (0.0f - gain) * release;
        }
        
        samples[i] *= gain;
    }
}

void FGComAudio::ProfessionalAudioEngine::NoiseGateProcessor::reset() {
    envelope = 0.0f;
    gain = 1.0f;
}

// EQProcessor Implementation
FGComAudio::ProfessionalAudioEngine::EQProcessor::EQProcessor() {}

void FGComAudio::ProfessionalAudioEngine::EQProcessor::setBands(const std::vector<float>& frequencies, const std::vector<float>& gains) {
    this->frequencies = frequencies;
    this->gains = gains;
    bands.resize(frequencies.size());
    
    for (size_t i = 0; i < frequencies.size(); ++i) {
        if (gains[i] > 0.0f) {
            bands[i].setBandPass(frequencies[i] * 0.8f, frequencies[i] * 1.2f, 44100.0f, 1.0f);
        } else {
            bands[i].setNotch(frequencies[i], 44100.0f, 10.0f);
        }
    }
}

void FGComAudio::ProfessionalAudioEngine::EQProcessor::process(float* samples, uint32_t sampleCount, uint16_t channelCount) {
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        float input = samples[i];
        float output = input;
        
        for (size_t j = 0; j < bands.size(); ++j) {
            float filtered = bands[j].process(input);
            float gainDb = gains[j];
            float gainLinear = powf(10.0f, gainDb / 20.0f);
            output += filtered * (gainLinear - 1.0f);
        }
        
        samples[i] = output;
    }
}

void FGComAudio::ProfessionalAudioEngine::EQProcessor::reset() {
    for (auto& band : bands) {
        band.reset();
    }
}

// ProfessionalAudioEngine Implementation
ProfessionalAudioEngine::ProfessionalAudioEngine() 
    : radioEffectsEnabled(false), currentSignalQuality(1.0f), currentDistance(0.0f),
      currentVolume(1.0f), currentNoiseLevel(0.0f) {
    // Initialize with default settings
    highPassFilter.setHighPass(80.0f, 44100.0f);
    lowPassFilter.setLowPass(8000.0f, 44100.0f);
    bandPassFilter.setBandPass(300.0f, 3000.0f, 44100.0f);
}

void ProfessionalAudioEngine::processAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRate) {
    // Apply radio-specific filtering using IIR1 filters (much more appropriate for radio)
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        samples[i] = radioHighPassFilter.process(samples[i]);
        samples[i] = radioLowPassFilter.process(samples[i]);
    }
    
    // Apply general audio filtering
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        samples[i] = highPassFilter.process(samples[i]);
        samples[i] = lowPassFilter.process(samples[i]);
    }
    
    // Apply volume
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        samples[i] *= currentVolume;
    }
    
    // Apply radio effects if enabled
    if (radioEffectsEnabled) {
        applyRadioEffects(samples, sampleCount, channelCount);
    }
    
    // Apply signal quality degradation
    applySignalQualityDegradation(samples, sampleCount, channelCount);
}

void ProfessionalAudioEngine::setHighPassFilter(float cutoffHz, float sampleRate) {
    highPassFilter.setHighPass(cutoffHz, sampleRate);
}

void ProfessionalAudioEngine::setLowPassFilter(float cutoffHz, float sampleRate) {
    lowPassFilter.setLowPass(cutoffHz, sampleRate);
}

void ProfessionalAudioEngine::setBandPassFilter(float lowCutoffHz, float highCutoffHz, float sampleRate) {
    bandPassFilter.setBandPass(lowCutoffHz, highCutoffHz, sampleRate);
}

void ProfessionalAudioEngine::setRadioBandPassFilter(float lowCutoffHz, float highCutoffHz, float sampleRate) {
    // Use IIR1 filters for radio bandpass - much more appropriate than biquad
    radioHighPassFilter.setHighPass(lowCutoffHz, sampleRate);
    radioLowPassFilter.setLowPass(highCutoffHz, sampleRate);
}

void ProfessionalAudioEngine::setRadioHighPassFilter(float cutoffHz, float sampleRate) {
    radioHighPassFilter.setHighPass(cutoffHz, sampleRate);
}

void ProfessionalAudioEngine::setRadioLowPassFilter(float cutoffHz, float sampleRate) {
    radioLowPassFilter.setLowPass(cutoffHz, sampleRate);
}

void ProfessionalAudioEngine::setVolume(float volume) {
    currentVolume = std::max(0.0f, std::min(2.0f, volume));
}

void ProfessionalAudioEngine::setNoiseLevel(float noiseLevel) {
    currentNoiseLevel = std::max(0.0f, std::min(1.0f, noiseLevel));
}

void ProfessionalAudioEngine::setSignalQuality(float quality) {
    currentSignalQuality = std::max(0.0f, std::min(1.0f, quality));
}

void ProfessionalAudioEngine::enableReverb(bool enable, float roomSize, float damping) {
    if (enable) {
        reverb.setParameters(roomSize, damping, 0.3f, 0.7f);
    }
}

void ProfessionalAudioEngine::enableChorus(bool enable, float rate, float depth) {
    if (enable) {
        chorus.setParameters(rate, depth, 0.0f, 0.3f);
    }
}

void ProfessionalAudioEngine::enableCompression(bool enable, float threshold, float ratio) {
    if (enable) {
        compressor.setParameters(threshold, ratio, 0.003f, 0.1f);
    }
}

void ProfessionalAudioEngine::enableNoiseGate(bool enable, float threshold) {
    if (enable) {
        noiseGate.setParameters(threshold, 0.001f, 0.1f);
    }
}

void ProfessionalAudioEngine::enableEQ(bool enable, const std::vector<float>& frequencies, const std::vector<float>& gains) {
    if (enable) {
        eq.setBands(frequencies, gains);
    }
}

void ProfessionalAudioEngine::enableRadioEffects(bool enable) {
    radioEffectsEnabled = enable;
}

void ProfessionalAudioEngine::setRadioType(const std::string& radioType) {
    currentRadioType = radioType;
}

void ProfessionalAudioEngine::setPropagationEffects(float distance, float signalQuality) {
    currentDistance = distance;
    currentSignalQuality = signalQuality;
}

void ProfessionalAudioEngine::applyRadioEffects(float* samples, uint32_t sampleCount, uint16_t channelCount) {
    if (currentRadioType == "VHF") {
        // VHF-specific effects
        chorus.process(samples, sampleCount, channelCount);
        reverb.setParameters(0.2f, 0.6f, 0.2f, 0.8f);
        reverb.process(samples, sampleCount, channelCount);
    } else if (currentRadioType == "HF") {
        // HF-specific effects
        chorus.setParameters(0.2f, 0.3f, 0.1f, 0.4f);
        chorus.process(samples, sampleCount, channelCount);
        reverb.setParameters(0.5f, 0.4f, 0.3f, 0.7f);
        reverb.process(samples, sampleCount, channelCount);
    }
}

void ProfessionalAudioEngine::applyPropagationEffects(float* samples, uint32_t sampleCount, uint16_t channelCount) {
    // Apply distance-based attenuation
    float distanceAttenuation = 1.0f / (1.0f + currentDistance * 0.1f);
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        samples[i] *= distanceAttenuation;
    }
}

void ProfessionalAudioEngine::applySignalQualityDegradation(float* samples, uint32_t sampleCount, uint16_t channelCount) {
    float degradation = 1.0f - currentSignalQuality;
    
    // Apply harmonic distortion
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        float sample = samples[i];
        float distortion = sample * sample * degradation * 0.1f;
        samples[i] = sample + distortion;
    }
    
    // Apply noise
    if (currentNoiseLevel > 0.0f) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_real_distribution<float> dis(-1.0f, 1.0f);
        
        for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
            samples[i] += dis(gen) * currentNoiseLevel * 0.1f;
        }
    }
}

// Radio-specific processor implementations
VHFAudioProcessor::VHFAudioProcessor() {
    // Use IIR1 filters for VHF radio bandpass filtering
    setRadioBandPassFilter(300.0f, 3000.0f, 44100.0f);
    enableReverb(true, 0.2f, 0.6f);
    enableChorus(true, 0.5f, 0.1f);
    enableCompression(true, -20.0f, 3.0f);
    enableNoiseGate(true, -35.0f);
}

void VHFAudioProcessor::processVHFAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, 
                                        uint32_t sampleRate, float signalQuality) {
    setSignalQuality(signalQuality);
    processAudio(samples, sampleCount, channelCount, sampleRate);
}

HFAudioProcessor::HFAudioProcessor() {
    // Use IIR1 filters for HF radio bandpass filtering
    setRadioBandPassFilter(200.0f, 3000.0f, 44100.0f);
    enableReverb(true, 0.5f, 0.4f);
    enableChorus(true, 0.2f, 0.3f);
    enableCompression(true, -15.0f, 4.0f);
    enableNoiseGate(true, -30.0f);
}

void HFAudioProcessor::processHFAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, 
                                      uint32_t sampleRate, float signalQuality) {
    setSignalQuality(signalQuality);
    processAudio(samples, sampleCount, channelCount, sampleRate);
}

AmateurRadioProcessor::AmateurRadioProcessor() {
    // Use IIR1 filters for amateur radio bandpass filtering
    setRadioBandPassFilter(300.0f, 3000.0f, 44100.0f);
    enableCompression(true, -25.0f, 2.5f);
    enableNoiseGate(true, -40.0f);
}

void AmateurRadioProcessor::processAmateurAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, 
                                                 uint32_t sampleRate, float signalQuality) {
    setSignalQuality(signalQuality);
    processAudio(samples, sampleCount, channelCount, sampleRate);
}

WebRTCAudioProcessor::WebRTCAudioProcessor() 
    : inputGain(1.0f), outputGain(1.0f), noiseSuppressionEnabled(true), echoCancellationEnabled(true) {
    setHighPassFilter(80.0f, 44100.0f);
    setLowPassFilter(8000.0f, 44100.0f);
    enableCompression(true, -20.0f, 3.0f);
    enableNoiseGate(true, -30.0f);
}

void WebRTCAudioProcessor::processWebRTCAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, 
                                              uint32_t sampleRate) {
    // Apply input gain
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        samples[i] *= inputGain;
    }
    
    processAudio(samples, sampleCount, channelCount, sampleRate);
    
    // Apply output gain
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        samples[i] *= outputGain;
    }
}

void WebRTCAudioProcessor::setInputGain(float gain) {
    inputGain = gain;
}

void WebRTCAudioProcessor::setOutputGain(float gain) {
    outputGain = gain;
}

void WebRTCAudioProcessor::enableNoiseSuppression(bool enable) {
    noiseSuppressionEnabled = enable;
}

void WebRTCAudioProcessor::enableEchoCancellation(bool enable) {
    echoCancellationEnabled = enable;
}

SovietVHFProcessor::SovietVHFProcessor(const std::string& radioType)
    : radioType(radioType), fmMode(true), cwMode(false), currentPower(1.5), isOperational(true) {
    // Use IIR1 filters for Soviet VHF radio bandpass filtering
    setRadioBandPassFilter(300.0f, 3000.0f, 44100.0f);
    enableReverb(true, 0.4f, 0.6f);
    enableChorus(true, 0.5f, 0.2f);
    enableCompression(true, -18.0f, 2.8f);
    enableNoiseGate(true, -32.0f);
}

void SovietVHFProcessor::processSovietVHFAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, 
                                               uint32_t sampleRate, float signalQuality, double power) {
    if (!isOperational || signalQuality <= 0.0) {
        // Mute audio if not operational
        for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
            samples[i] = 0.0f;
        }
        return;
    }
    
    // Apply power scaling
    float powerScale = static_cast<float>(power / 1.5);
    for (uint32_t i = 0; i < sampleCount * channelCount; ++i) {
        samples[i] *= powerScale;
    }
    
    setSignalQuality(signalQuality);
    processAudio(samples, sampleCount, channelCount, sampleRate);
}

} // namespace FGComAudio

// C API Implementation
extern "C" {

void fgcom_audio_professional_initialize() {
    // Initialize global processors
    FGComAudio::g_audioProcessor = std::make_unique<FGComAudio::ProfessionalAudioEngine>();
    FGComAudio::g_vhfProcessor = std::make_unique<FGComAudio::VHFAudioProcessor>();
    FGComAudio::g_hfProcessor = std::make_unique<FGComAudio::HFAudioProcessor>();
    FGComAudio::g_amateurProcessor = std::make_unique<FGComAudio::AmateurRadioProcessor>();
    FGComAudio::g_webrtcProcessor = std::make_unique<FGComAudio::WebRTCAudioProcessor>();
    FGComAudio::g_sovietProcessor = std::make_unique<FGComAudio::SovietVHFProcessor>("R-105");
}

void fgcom_audio_professional_filter(int highpass_cutoff, int lowpass_cutoff, 
                                    float *outputPCM, uint32_t sampleCount, 
                                    uint16_t channelCount, uint32_t sampleRateHz) {
    if (!FGComAudio::g_audioProcessor) return;
    
    if (highpass_cutoff > 0) {
        FGComAudio::g_audioProcessor->setHighPassFilter(static_cast<float>(highpass_cutoff), sampleRateHz);
    }
    
    if (lowpass_cutoff > 0) {
        FGComAudio::g_audioProcessor->setLowPassFilter(static_cast<float>(lowpass_cutoff), sampleRateHz);
    }
    
    FGComAudio::g_audioProcessor->processAudio(outputPCM, sampleCount, channelCount, sampleRateHz);
}

void fgcom_audio_professional_applyVolume(float volume, float *outputPCM, 
                                         uint32_t sampleCount, uint16_t channelCount) {
    if (!FGComAudio::g_audioProcessor) return;
    
    FGComAudio::g_audioProcessor->setVolume(volume);
    FGComAudio::g_audioProcessor->processAudio(outputPCM, sampleCount, channelCount, 44100);
}

void fgcom_audio_professional_addNoise(float noiseVolume, float *outputPCM, 
                                      uint32_t sampleCount, uint16_t channelCount) {
    if (!FGComAudio::g_audioProcessor) return;
    
    FGComAudio::g_audioProcessor->setNoiseLevel(noiseVolume);
    FGComAudio::g_audioProcessor->processAudio(outputPCM, sampleCount, channelCount, 44100);
}

void fgcom_audio_professional_applySignalQualityDegradation(float *outputPCM, 
                                                            uint32_t sampleCount, 
                                                            uint16_t channelCount, 
                                                            float dropoutProbability) {
    if (!FGComAudio::g_audioProcessor) return;
    
    FGComAudio::g_audioProcessor->setSignalQuality(1.0f - dropoutProbability);
    FGComAudio::g_audioProcessor->processAudio(outputPCM, sampleCount, channelCount, 44100);
}

void fgcom_audio_professional_makeMono(float *outputPCM, uint32_t sampleCount, 
                                      uint16_t channelCount) {
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

void fgcom_audio_professional_processVHF(float *outputPCM, uint32_t sampleCount, 
                                         uint16_t channelCount, uint32_t sampleRateHz, 
                                         float signalQuality) {
    if (!FGComAudio::g_vhfProcessor) return;
    
    FGComAudio::g_vhfProcessor->processVHFAudio(outputPCM, sampleCount, channelCount, sampleRateHz, signalQuality);
}

void fgcom_audio_professional_processHF(float *outputPCM, uint32_t sampleCount, 
                                        uint16_t channelCount, uint32_t sampleRateHz, 
                                        float signalQuality) {
    if (!FGComAudio::g_hfProcessor) return;
    
    FGComAudio::g_hfProcessor->processHFAudio(outputPCM, sampleCount, channelCount, sampleRateHz, signalQuality);
}

void fgcom_audio_professional_processAmateur(float *outputPCM, uint32_t sampleCount, 
                                             uint16_t channelCount, uint32_t sampleRateHz, 
                                             float signalQuality) {
    if (!FGComAudio::g_amateurProcessor) return;
    
    FGComAudio::g_amateurProcessor->processAmateurAudio(outputPCM, sampleCount, channelCount, sampleRateHz, signalQuality);
}

void fgcom_audio_professional_processWebRTC(float *outputPCM, uint32_t sampleCount, 
                                            uint16_t channelCount, uint32_t sampleRateHz) {
    if (!FGComAudio::g_webrtcProcessor) return;
    
    FGComAudio::g_webrtcProcessor->processWebRTCAudio(outputPCM, sampleCount, channelCount, sampleRateHz);
}

void fgcom_audio_professional_processSovietVHF(float *outputPCM, uint32_t sampleCount, 
                                               uint16_t channelCount, uint32_t sampleRateHz, 
                                               float signalQuality, double power, 
                                               const char* radioType) {
    if (!FGComAudio::g_sovietProcessor) return;
    
    FGComAudio::g_sovietProcessor->processSovietVHFAudio(outputPCM, sampleCount, channelCount, 
                                                         sampleRateHz, signalQuality, power);
}

} // extern "C"
