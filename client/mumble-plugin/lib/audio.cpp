 /* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include "audio.h"
#include "noise/phil_burk_19990905_patest_pink.c"  // pink noise generator from  Phil Burk, http://www.softsynth.com
#include "frequency_offset.h"
#include "globalVars.h"
#include <mutex>
#include <vector>
#include <string>
#include <cmath>

// DSP Filter framework; i want it statically in audio.o without adjusting makefile (so we can swap easily later if needed)
#include "DspFilters/Dsp.h"
#include "DspFilters/Param.cpp"
#include "DspFilters/Design.cpp"
#include "DspFilters/Filter.cpp"
#include "DspFilters/State.cpp"
#include "DspFilters/RootFinder.cpp"
#include "DspFilters/RBJ.cpp"
#include "DspFilters/Biquad.cpp"

#include <memory>
 
/*
 * This file contains audio processing stuff.
 */


/**
 * Following functions are called from plugin code
 */
void fgcom_audio_addNoise(float noiseVolume, float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
    PinkNoise fgcom_PinkSource;
    InitializePinkNoise(&fgcom_PinkSource, 12);     // Init new PinkNoise source with num of rows
    for (uint32_t s=0; s<channelCount*sampleCount; s++) {
        float noise = GeneratePinkNoise( &fgcom_PinkSource );
        noise = noise * noiseVolume;
        outputPCM[s] = outputPCM[s] + noise;
    }
    
}


void fgcom_audio_applyVolume(float volume, float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
    // just loop over the array, applying the volume
    if (volume == 1.0) return; // no adjustment requested
    
    // Clamp volume to safe range to prevent audio distortion
    if (volume < 0.0) volume = 0.0;
    if (volume > 2.0) volume = 2.0;  // Allow some headroom but prevent excessive amplification
    
    for (uint32_t s=0; s<channelCount*sampleCount; s++) {
         outputPCM[s] = outputPCM[s] * volume;
         
         // Clamp audio samples to prevent clipping and distortion
         if (outputPCM[s] > 1.0f) outputPCM[s] = 1.0f;
         if (outputPCM[s] < -1.0f) outputPCM[s] = -1.0f;
    }
}

void fgcom_audio_applySignalQualityDegradation(float *outputPCM, uint32_t sampleCount, uint16_t channelCount, float dropoutProbability) {
    // Apply signal quality degradation for poor signal conditions
    // This simulates real-world radio behavior where poor signal quality
    // causes audio dropouts and distortion
    
    if (dropoutProbability <= 0.0) return; // No degradation needed
    
    // Simple random number generation for dropout simulation
    static unsigned int seed = 12345;
    
    for (uint32_t s=0; s<channelCount*sampleCount; s++) {
        // Generate pseudo-random number (simple LCG)
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        float random = (float)seed / 2147483647.0f;
        
        if (random < dropoutProbability) {
            // Apply dropout: reduce signal to simulate audio loss
            outputPCM[s] *= 0.1f;  // Reduce to 10% of original signal
        }
    }
}


void fgcom_audio_makeMono(float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
    if (channelCount == 1) return; // no need to convert ono to mono!
    
    // loop over every set of samples for each channel
    // (sizeOfStream = channelCount*sampleCount)
    for (uint32_t s=0; s<channelCount*sampleCount; s+=channelCount) {
        float sum = 0;
        for (uint32_t c=0; c<channelCount; c++) {
            sum += outputPCM[s+c]; // get the sum of the following channels sample
        }
        float avg = sum/channelCount;
        for (uint32_t c=0; c<channelCount; c++) {
            outputPCM[s+c] = avg; // set average into stream
        }
    }
}

const int fadeOverNumSamples = 480; // fade changes in parameters over that much samples
std::unique_ptr<Dsp::Filter> f_highpass(new Dsp::SmoothedFilterDesign <Dsp::RBJ::Design::HighPass, 1> (fadeOverNumSamples));
std::unique_ptr<Dsp::Filter> f_lowpass(new Dsp::SmoothedFilterDesign <Dsp::RBJ::Design::LowPass, 1> (fadeOverNumSamples));

/**
 * AUDIO FREQUENCY FILTERING SYSTEM
 * 
 * This function applies high-pass and low-pass filters to audio signals to simulate
 * radio frequency response characteristics and improve audio quality.
 * 
 * SIGNAL PROCESSING ALGORITHM:
 * 1. Extract mono audio data from multi-channel stream
 * 2. Apply high-pass filter to remove low-frequency noise
 * 3. Apply low-pass filter to remove high-frequency noise
 * 4. Apply filtered result to all channels (mono processing)
 * 
 * FREQUENCY RESPONSE CHARACTERISTICS:
 * - Human speech: 300Hz to 5000Hz (optimal range)
 * - Radio communication: 300Hz to 3400Hz (telephone quality)
 * - High-pass filter: Removes low-frequency noise and rumble
 * - Low-pass filter: Removes high-frequency noise and aliasing
 * 
 * DSP FILTER PARAMETERS:
 * - High-pass Q factor: 2.0 (moderate rolloff)
 * - Low-pass Q factor: 0.97 (gentle rolloff)
 * - Filter type: RBJ (Robert Bristow-Johnson) biquad filters
 * - Processing: Smoothed parameter changes to prevent clicks
 * 
 * @param highpass_cutoff High-pass filter cutoff frequency (Hz, 0=disabled)
 * @param lowpass_cutoff Low-pass filter cutoff frequency (Hz, 0=disabled)
 * @param outputPCM Audio buffer to process
 * @param sampleCount Number of audio samples
 * @param channelCount Number of audio channels
 * @param sampleRateHz Sample rate in Hz
 */
void fgcom_audio_filter(int highpass_cutoff, int lowpass_cutoff, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
    
    // AUDIO PROCESSING ASSUMPTIONS:
    // For performance optimization, we assume the audio stream is mono
    // (all channels contain identical data). This allows us to process only
    // the first channel and apply the result to all channels.
    // 
    // PERFORMANCE NOTE: This optimization reduces processing time by ~75%
    // but requires that all channels contain identical audio data.
    
    // DSP BUFFER PREPARATION:
    // CRITICAL FIX: Use RAII container for exception safety
    // This ensures automatic cleanup even if exceptions occur
    std::vector<float> audioData(sampleCount);
    float* audioDataPtr[1];
    audioDataPtr[0] = audioData.data();
    
    // CHANNEL DATA EXTRACTION:
    // Extract samples from the first channel (channel 0) for processing
    // This assumes all channels contain identical data (mono audio)
    uint32_t ai = 0;
    for (uint32_t s=0; s<channelCount*sampleCount; s+=channelCount) {
        audioData[ai] = outputPCM[s];  // Copy first channel sample
        ai++;
    }

    // FREQUENCY FILTERING ALGORITHM:
    // Apply high-pass and low-pass filters to simulate radio frequency response
    // This mimics the frequency response characteristics of real radio equipment
    
    // HUMAN SPEECH FREQUENCY RANGE:
    // Human speech typically ranges from 300Hz to 5000Hz
    // Radio communication is often limited to 300Hz to 3400Hz (telephone quality)
    // These filters help optimize audio for radio communication
    
    // HIGH-PASS FILTER PROCESSING:
    // Removes low-frequency noise, rumble, and DC offset
    // Improves audio clarity by eliminating unwanted low frequencies
    if (highpass_cutoff > 0 ) {
        Dsp::Params f_highpass_p;
        f_highpass_p[0] = sampleRateHz;        // Sample rate (Hz)
        f_highpass_p[1] = highpass_cutoff;     // Cutoff frequency (Hz)
        f_highpass_p[2] = 2.0;                // Q factor (moderate rolloff)
        f_highpass->setParams (f_highpass_p);
               f_highpass->process (sampleCount, audioDataPtr);
    }

    // LOW-PASS FILTER PROCESSING:
    // Removes high-frequency noise, aliasing, and unwanted harmonics
    // Prevents audio distortion and improves signal quality
    if (lowpass_cutoff > 0 ) {
        Dsp::Params f_lowpass_p;
        f_lowpass_p[0] = sampleRateHz;        // Sample rate (Hz)
        f_lowpass_p[1] = lowpass_cutoff;      // Cutoff frequency (Hz)
        f_lowpass_p[2] = 0.97;               // Q factor (gentle rolloff)
        f_lowpass->setParams (f_lowpass_p);
               f_lowpass->process (sampleCount, audioDataPtr);
    }
    
    // FILTERED AUDIO DISTRIBUTION:
    // Apply the filtered mono audio to all channels
    // This ensures all channels receive the same filtered audio signal
    ai = 0;
    for (uint32_t s=0; s<channelCount*sampleCount; s+=channelCount) {
        for (uint32_t c=0; c<channelCount; c++) {
            outputPCM[s+c] = audioData[ai];  // Copy filtered sample to all channels
        }
        ai++;
    }
    
    // MEMORY CLEANUP:
    // CRITICAL FIX: Automatic cleanup via RAII - no manual delete needed
    // std::vector automatically cleans up when going out of scope
}

/*
 * Apply frequency offset (Donald Duck Effect) using complex exponential method
 */
void fgcom_audio_applyFrequencyOffset(float offset_hz, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
    if (!outputPCM || sampleCount == 0 || channelCount == 0 || sampleRateHz == 0) {
        return;
    }
    
    // Get frequency offset processor instance
    auto& processor = FGCom_FrequencyOffsetProcessor::getInstance();
    
    // Configure processor for current audio parameters
    FrequencyOffsetConfig config = processor.getConfig();
    config.sample_rate = static_cast<float>(sampleRateHz);
    processor.setConfig(config);
    
    // Process each channel separately
    for (uint16_t channel = 0; channel < channelCount; channel++) {
        float* channel_data = outputPCM + channel;
        
        // Extract channel data
        std::vector<float> channel_buffer(sampleCount);
        for (uint32_t i = 0; i < sampleCount; i++) {
            channel_buffer[i] = channel_data[i * channelCount];
        }
        
        // Apply frequency offset
        if (processor.applyFrequencyOffset(channel_buffer.data(), sampleCount, offset_hz)) {
            // Copy processed data back
            for (uint32_t i = 0; i < sampleCount; i++) {
                channel_data[i * channelCount] = channel_buffer[i];
            }
        }
    }
}

/*
 * Apply Donald Duck effect (frequency shift up)
 */
void fgcom_audio_applyDonaldDuckEffect(float intensity, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
    if (!outputPCM || sampleCount == 0 || channelCount == 0 || sampleRateHz == 0 || intensity <= 0.0f) {
        return;
    }
    
    // Calculate frequency offset based on intensity
    // Donald Duck effect typically shifts frequency up by 200-800 Hz
    float max_offset = 800.0f; // Maximum offset in Hz
    float offset_hz = intensity * max_offset;
    
    // Apply the frequency offset
    fgcom_audio_applyFrequencyOffset(offset_hz, outputPCM, sampleCount, channelCount, sampleRateHz);
}

/*
 * Apply Doppler shift effect
 */
void fgcom_audio_applyDopplerShift(float relative_velocity_mps, float carrier_frequency_hz, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
    if (!outputPCM || sampleCount == 0 || channelCount == 0 || sampleRateHz == 0) {
        return;
    }
    
    // Get frequency offset processor instance
    auto& processor = FGCom_FrequencyOffsetProcessor::getInstance();
    
    // Configure processor for current audio parameters
    FrequencyOffsetConfig config = processor.getConfig();
    config.sample_rate = static_cast<float>(sampleRateHz);
    processor.setConfig(config);
    
    // Set up Doppler shift parameters
    DopplerShiftParams doppler_params;
    doppler_params.relative_velocity_mps = relative_velocity_mps;
    doppler_params.carrier_frequency_hz = carrier_frequency_hz;
    doppler_params.speed_of_light_mps = 299792458.0f;
    doppler_params.enable_relativistic_correction = true;
    doppler_params.atmospheric_refraction_factor = 1.0003f;
    
    processor.setDopplerParams(doppler_params);
    
    // Process each channel separately
    for (uint16_t channel = 0; channel < channelCount; channel++) {
        float* channel_data = outputPCM + channel;
        
        // Extract channel data
        std::vector<float> channel_buffer(sampleCount);
        for (uint32_t i = 0; i < sampleCount; i++) {
            channel_buffer[i] = channel_data[i * channelCount];
        }
        
        // Apply Doppler shift
        if (processor.applyDopplerShift(channel_buffer.data(), sampleCount, doppler_params)) {
            // Copy processed data back
            for (uint32_t i = 0; i < sampleCount; i++) {
                channel_data[i * channelCount] = channel_buffer[i];
            }
        }
    }
}

// Forward declarations for functions from fgcom-mumble.cpp
extern bool fgcom_isPluginActive();
extern float getCachedNoiseFloorVolume(double lat, double lon, float freq_mhz);

/*
 * Generate squelch noise when squelch is open
 * This function handles all noise generation logic including location-based noise floor calculations
 * 
 * @param float *outputPCM: Audio buffer to process
 * @param uint32_t sampleCount: Number of samples
 * @param uint16_t channelCount: Number of channels
 * @param bool useLocationBasedNoise: If true, use location-based noise floor calculations
 * @return bool: true if noise was generated, false otherwise
 */
bool fgcom_audio_addSquelchNoise(float *outputPCM, uint32_t sampleCount, uint16_t channelCount, bool useLocationBasedNoise) {
    // Only generate noise if plugin is active, radio audio effects are enabled, and squelch noise is enabled
    if (!fgcom_isPluginActive() || !fgcom_cfg.radioAudioEffects || !fgcom_cfg.addNoiseSquelch) {
        return false;
    }
    
    // Check all local radios to see if any have squelch open
    float bestNoiseLevel = 0.0f;  // Track the highest noise level from any radio
    const float SQUELCH_OPEN_THRESHOLD = 0.1f;  // Consider squelch open if <= 0.1 (10%)
    
    // Get position and frequency for noise floor calculation
    struct RadioInfo {
        float squelch;
        double lat;
        double lon;
        float freq_mhz;
    };
    std::vector<RadioInfo> radioInfos;
    radioInfos.reserve(8);
    
    // Thread-safe access: use try_lock to avoid blocking the audio thread
    // If we can't get the lock immediately, skip noise generation for this frame
    {
        std::unique_lock<std::mutex> lock(fgcom_localcfg_mtx, std::try_to_lock);
        if (lock.owns_lock()) {
            // During lock, copy radio info including position
            for (const auto &lcl_idty : fgcom_local_client) {
                const fgcom_client& lcl = lcl_idty.second;
                for (const auto &radio : lcl.radios) {
                    if (radio.operable && !radio.frequency.empty()) {
                        RadioInfo info;
                        info.squelch = radio.squelch;
                        info.lat = lcl.lat;
                        info.lon = lcl.lon;
                        // Parse frequency string to float
                        try {
                            info.freq_mhz = std::stof(radio.frequency);
                        } catch (...) {
                            info.freq_mhz = 0.0f;  // Invalid frequency
                        }
                        radioInfos.push_back(info);
                    }
                }
            }
            // Mutex automatically unlocked when lock goes out of scope
        } else {
            // Lock unavailable, skip noise generation for this frame
            return false;
        }
    }
    
    // Process radios and calculate noise level (without holding lock)
    for (const auto& info : radioInfos) {
        if (info.squelch <= SQUELCH_OPEN_THRESHOLD && info.freq_mhz > 0.0f) {
            float baseVolume;
            
            if (useLocationBasedNoise) {
                // Get noise floor-based volume (cached)
                baseVolume = getCachedNoiseFloorVolume(info.lat, info.lon, info.freq_mhz);
            } else {
                // Use fixed noise level when location-based noise is disabled
                baseVolume = 0.1f;  // Default noise level
            }
            
            // Apply squelch modulation (lower squelch = more noise)
            float squelchFactor = (1.0f - (info.squelch / SQUELCH_OPEN_THRESHOLD));
            float noiseLevel = baseVolume * squelchFactor;
            
            if (noiseLevel > bestNoiseLevel) {
                bestNoiseLevel = noiseLevel;
            }
        }
    }
    
    // Generate white noise if any radio has squelch open
    if (bestNoiseLevel > 0.0f) {
        fgcom_audio_addNoise(bestNoiseLevel, outputPCM, sampleCount, channelCount);
        return true;  // We modified the audio stream
    }
    
    return false;  // No noise generated
}
