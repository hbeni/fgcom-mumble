/* 
 * Professional Audio Processing for FGCom-mumble
 * This file is part of the FGCom-mumble distribution (https://github.com/Supermagnum/fgcom-mumble).
 * Copyright (c) 2024 FGCom-mumble Contributors
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 */

#pragma once

#include <vector>
#include <memory>
#include <complex>
#include <cmath>
#include <algorithm>
#include <random>
#include <chrono>

namespace FGComAudio {

// IIR1 Filter for radio bandpass filtering - much more appropriate than biquad
class IIR1Filter {
public:
    IIR1Filter();
    void setLowPass(float cutoff, float sampleRate);
    void setHighPass(float cutoff, float sampleRate);
    void setBandPass(float lowCutoff, float highCutoff, float sampleRate);
    float process(float input);
    void reset();
    
private:
    void calculateCoefficients(float cutoff, float sampleRate, bool isHighPass);
    float a0, a1, b1;  // IIR1 coefficients: y[n] = a0*x[n] + a1*x[n-1] - b1*y[n-1]
    float x1, y1;      // Previous input and output samples
    bool isHighPass;
};

// BiquadFilter for advanced filtering (kept for compatibility)
class BiquadFilter {
public:
    BiquadFilter();
    void setLowPass(float cutoff, float sampleRate, float Q = 0.707f);
    void setHighPass(float cutoff, float sampleRate, float Q = 0.707f);
    void setBandPass(float lowCutoff, float highCutoff, float sampleRate, float Q = 0.707f);
    void setNotch(float frequency, float sampleRate, float Q = 10.0f);
    void setAllPass(float frequency, float sampleRate, float Q = 0.707f);
    float process(float input);
    void reset();

private:
    float a0, a1, a2, b1, b2;
    float x1, x2, y1, y2;
    void calculateCoefficients(float b0, float b1, float b2, float a0, float a1, float a2);
};

/**
 * Professional Audio Processing Engine
 * 
 * This class provides industry-standard audio processing capabilities
 * without external dependencies, offering high-quality DSP processing
 * with excellent compatibility and performance.
 */
class ProfessionalAudioEngine {
public:
    ProfessionalAudioEngine();
    ~ProfessionalAudioEngine() = default;

    // Core audio processing
    void processAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRate);
    void setHighPassFilter(float cutoffHz, float sampleRate);
    void setLowPassFilter(float cutoffHz, float sampleRate);
    void setBandPassFilter(float lowCutoffHz, float highCutoffHz, float sampleRate);
    void setVolume(float volume);
    void setNoiseLevel(float noiseLevel);
    void setSignalQuality(float quality);
    
    // Radio-specific filtering using IIR1 filters
    void setRadioBandPassFilter(float lowCutoffHz, float highCutoffHz, float sampleRate);
    void setRadioHighPassFilter(float cutoffHz, float sampleRate);
    void setRadioLowPassFilter(float cutoffHz, float sampleRate);

    // Advanced effects
    void enableReverb(bool enable, float roomSize = 0.3f, float damping = 0.5f);
    void enableChorus(bool enable, float rate = 0.5f, float depth = 0.1f);
    void enableCompression(bool enable, float threshold = -20.0f, float ratio = 3.0f);
    void enableNoiseGate(bool enable, float threshold = -40.0f);
    void enableEQ(bool enable, const std::vector<float>& frequencies, const std::vector<float>& gains);

    // Radio simulation effects
    void enableRadioEffects(bool enable);
    void setRadioType(const std::string& radioType);
    void setPropagationEffects(float distance, float signalQuality);

private:
    // Internal processing components

    class ReverbProcessor {
    public:
        ReverbProcessor();
        void setParameters(float roomSize, float damping, float wetLevel, float dryLevel);
        void process(float* samples, uint32_t sampleCount, uint16_t channelCount);
        void reset();

    private:
        std::vector<float> delayLines[8];
        std::vector<int> delayTimes;
        std::vector<float> feedback;
        std::vector<float> damping;
        int currentSample;
        float roomSize, dampingAmount, wetLevel, dryLevel;
    };

    class ChorusProcessor {
    public:
        ChorusProcessor();
        void setParameters(float rate, float depth, float feedback, float mix);
        void process(float* samples, uint32_t sampleCount, uint16_t channelCount);
        void reset();

    private:
        std::vector<float> delayLine;
        float lfoPhase;
        float rate, depth, feedback, mix;
        int delayLineSize;
        int currentSample;
    };

    class CompressorProcessor {
    public:
        CompressorProcessor();
        void setParameters(float threshold, float ratio, float attack, float release);
        void process(float* samples, uint32_t sampleCount, uint16_t channelCount);
        void reset();

    private:
        float threshold, ratio, attack, release;
        float envelope;
        float gain;
    };

    class NoiseGateProcessor {
    public:
        NoiseGateProcessor();
        void setParameters(float threshold, float attack, float release);
        void process(float* samples, uint32_t sampleCount, uint16_t channelCount);
        void reset();

    private:
        float threshold, attack, release;
        float envelope;
        float gain;
    };

    class EQProcessor {
    public:
        EQProcessor();
        void setBands(const std::vector<float>& frequencies, const std::vector<float>& gains);
        void process(float* samples, uint32_t sampleCount, uint16_t channelCount);
        void reset();

    private:
        std::vector<BiquadFilter> bands;
        std::vector<float> frequencies;
        std::vector<float> gains;
    };

    // Processing chain - using IIR1 for radio bandpass filtering
    IIR1Filter radioHighPassFilter;    // For radio frequency filtering
    IIR1Filter radioLowPassFilter;     // For radio frequency filtering
    BiquadFilter highPassFilter;       // For general audio processing
    BiquadFilter lowPassFilter;        // For general audio processing
    BiquadFilter bandPassFilter;       // For general audio processing
    ReverbProcessor reverb;
    ChorusProcessor chorus;
    CompressorProcessor compressor;
    NoiseGateProcessor noiseGate;
    EQProcessor eq;

    // State
    bool radioEffectsEnabled;
    std::string currentRadioType;
    float currentSignalQuality;
    float currentDistance;
    float currentVolume;
    float currentNoiseLevel;

    // Helper functions
    void applyRadioEffects(float* samples, uint32_t sampleCount, uint16_t channelCount);
    void applyPropagationEffects(float* samples, uint32_t sampleCount, uint16_t channelCount);
    void applySignalQualityDegradation(float* samples, uint32_t sampleCount, uint16_t channelCount);
};

/**
 * Radio-Specific Audio Processors
 */
class VHFAudioProcessor : public ProfessionalAudioEngine {
public:
    VHFAudioProcessor();
    void processVHFAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, 
                         uint32_t sampleRate, float signalQuality);
};

class HFAudioProcessor : public ProfessionalAudioEngine {
public:
    HFAudioProcessor();
    void processHFAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, 
                        uint32_t sampleRate, float signalQuality);
};

class AmateurRadioProcessor : public ProfessionalAudioEngine {
public:
    AmateurRadioProcessor();
    void processAmateurAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, 
                             uint32_t sampleRate, float signalQuality);
};

class WebRTCAudioProcessor : public ProfessionalAudioEngine {
public:
    WebRTCAudioProcessor();
    void processWebRTCAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, 
                            uint32_t sampleRate);
    void setInputGain(float gain);
    void setOutputGain(float gain);
    void enableNoiseSuppression(bool enable);
    void enableEchoCancellation(bool enable);

private:
    float inputGain, outputGain;
    bool noiseSuppressionEnabled, echoCancellationEnabled;
};

class SovietVHFProcessor : public ProfessionalAudioEngine {
public:
    SovietVHFProcessor(const std::string& radioType);
    void processSovietVHFAudio(float* samples, uint32_t sampleCount, uint16_t channelCount, 
                              uint32_t sampleRate, float signalQuality, double power);

private:
    std::string radioType;
    bool fmMode, cwMode;
    double currentPower;
    bool isOperational;
};

} // namespace FGComAudio

// C API compatibility functions
extern "C" {
    // Initialize professional audio system
    void fgcom_audio_professional_initialize();
    
    // Core audio processing
    void fgcom_audio_professional_filter(int highpass_cutoff, int lowpass_cutoff, 
                                        float *outputPCM, uint32_t sampleCount, 
                                        uint16_t channelCount, uint32_t sampleRateHz);
    
    void fgcom_audio_professional_applyVolume(float volume, float *outputPCM, 
                                            uint32_t sampleCount, uint16_t channelCount);
    
    void fgcom_audio_professional_addNoise(float noiseVolume, float *outputPCM, 
                                          uint32_t sampleCount, uint16_t channelCount);
    
    void fgcom_audio_professional_applySignalQualityDegradation(float *outputPCM, 
                                                               uint32_t sampleCount, 
                                                               uint16_t channelCount, 
                                                               float dropoutProbability);
    
    void fgcom_audio_professional_makeMono(float *outputPCM, uint32_t sampleCount, 
                                          uint16_t channelCount);
    
    // Radio-specific processing
    void fgcom_audio_professional_processVHF(float *outputPCM, uint32_t sampleCount, 
                                             uint16_t channelCount, uint32_t sampleRateHz, 
                                             float signalQuality);
    
    void fgcom_audio_professional_processHF(float *outputPCM, uint32_t sampleCount, 
                                           uint16_t channelCount, uint32_t sampleRateHz, 
                                           float signalQuality);
    
    void fgcom_audio_professional_processAmateur(float *outputPCM, uint32_t sampleCount, 
                                                uint16_t channelCount, uint32_t sampleRateHz, 
                                                float signalQuality);
    
    // WebRTC processing
    void fgcom_audio_professional_processWebRTC(float *outputPCM, uint32_t sampleCount, 
                                               uint16_t channelCount, uint32_t sampleRateHz);
    
    // Soviet VHF processing
    void fgcom_audio_professional_processSovietVHF(float *outputPCM, uint32_t sampleCount, 
                                                   uint16_t channelCount, uint32_t sampleRateHz, 
                                                   float signalQuality, double power, 
                                                   const char* radioType);
}
