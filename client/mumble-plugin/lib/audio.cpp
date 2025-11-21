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
    static PinkNoise fgcom_PinkSource;
    static bool pinkNoiseInitialized = false;
    
    if (!pinkNoiseInitialized) {
        InitializePinkNoise(&fgcom_PinkSource, 12);
        pinkNoiseInitialized = true;
    }
    
    for (uint32_t s=0; s<channelCount*sampleCount; s++) {
        float noise = GeneratePinkNoise( &fgcom_PinkSource );
        noise = noise * noiseVolume;
        outputPCM[s] = outputPCM[s] + noise;
    }
}


void fgcom_audio_applyVolume(float volume, float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
    if (volume == 1.0) return;
    
    if (volume < 0.0) volume = 0.0;
    if (volume > 2.0) volume = 2.0;
    
    for (uint32_t s=0; s<channelCount*sampleCount; s++) {
         outputPCM[s] = outputPCM[s] * volume;
         
         if (outputPCM[s] > 1.0f) outputPCM[s] = 1.0f;
         if (outputPCM[s] < -1.0f) outputPCM[s] = -1.0f;
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

void fgcom_audio_filter(int highpass_cutoff, int lowpass_cutoff, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
    // Extract mono audio from first channel
    std::vector<float> audioData(sampleCount);
    float* audioDataPtr[1];
    audioDataPtr[0] = audioData.data();
    
    uint32_t ai = 0;
    for (uint32_t s=0; s<channelCount*sampleCount; s+=channelCount) {
        audioData[ai] = outputPCM[s];
        ai++;
    }

    if (highpass_cutoff > 0 ) {
        Dsp::Params f_highpass_p;
        f_highpass_p[0] = sampleRateHz;
        f_highpass_p[1] = highpass_cutoff;
        f_highpass_p[2] = 2.0;
        f_highpass->setParams (f_highpass_p);
        f_highpass->process (sampleCount, audioDataPtr);
    }

    if (lowpass_cutoff > 0 ) {
        Dsp::Params f_lowpass_p;
        f_lowpass_p[0] = sampleRateHz;
        f_lowpass_p[1] = lowpass_cutoff;
        f_lowpass_p[2] = 0.97;
        f_lowpass->setParams (f_lowpass_p);
        f_lowpass->process (sampleCount, audioDataPtr);
    }
    
    // Apply filtered audio to all channels
    ai = 0;
    for (uint32_t s=0; s<channelCount*sampleCount; s+=channelCount) {
        for (uint32_t c=0; c<channelCount; c++) {
            outputPCM[s+c] = audioData[ai];
        }
        ai++;
    }
}

/*
 * Apply frequency offset (Donald Duck Effect) using complex exponential method
 */
void fgcom_audio_applyFrequencyOffset(float offset_hz, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
    // Stub implementation - frequency_offset.h not available
    // This function is not currently used in the codebase
    (void)offset_hz;
    (void)outputPCM;
    (void)sampleCount;
    (void)channelCount;
    (void)sampleRateHz;
}

// Forward declarations for functions from fgcom-mumble.cpp
extern bool fgcom_isPluginActive();

// CachedRadioInfo and cached_radio_infos are now declared in globalVars.h

static float smoothed_noise_level = 0.0f;

bool fgcom_audio_addSquelchNoise(float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
    if (!fgcom_isPluginActive() || !fgcom_cfg.radioAudioEffects || !fgcom_cfg.addNoiseSquelch) {
        smoothed_noise_level = 0.0f;
        return false;
    }
    
    float targetNoiseLevel = 0.0f;
    const float SQUELCH_OPEN_THRESHOLD = 0.1f;
    const float BASE_NOISE_VOLUME = 0.1f;
    
    std::unique_lock<std::mutex> lock(fgcom_localcfg_mtx, std::try_to_lock);
    if (!lock.owns_lock()) {
        return false;
    }
    
    for (const auto &lcl_idty : fgcom_local_client) {
        const fgcom_client& lcl = lcl_idty.second;
        for (const auto& radio : lcl.radios) {
            if (radio.operable && !radio.frequency.empty() && radio.squelch <= SQUELCH_OPEN_THRESHOLD) {
                float squelchFactor = (1.0f - (radio.squelch / SQUELCH_OPEN_THRESHOLD));
                float noiseLevel = BASE_NOISE_VOLUME * squelchFactor;
                
                if (noiseLevel > targetNoiseLevel) {
                    targetNoiseLevel = noiseLevel;
                }
            }
        }
    }
    
    const float SMOOTHING_FACTOR = 0.15f;
    
    if (targetNoiseLevel > 0.0f) {
        smoothed_noise_level = smoothed_noise_level + (targetNoiseLevel - smoothed_noise_level) * SMOOTHING_FACTOR;
        
        if (smoothed_noise_level > 0.001f) {
            fgcom_audio_addNoise(smoothed_noise_level, outputPCM, sampleCount, channelCount);
            return true;
        }
    } else {
        smoothed_noise_level = smoothed_noise_level * (1.0f - SMOOTHING_FACTOR);
        
        if (smoothed_noise_level > 0.001f) {
            fgcom_audio_addNoise(smoothed_noise_level, outputPCM, sampleCount, channelCount);
            return true;
        } else {
            smoothed_noise_level = 0.0f;
        }
    }
    
    return false;
}
