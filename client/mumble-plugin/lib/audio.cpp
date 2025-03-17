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
void fgcom_audio_addNoise(float oldNoiseVolume, float noiseVolume, float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
    PinkNoise fgcom_PinkSource;
    InitializePinkNoise(&fgcom_PinkSource, 12);     // Init new PinkNoise source with num of rows

    float interpolate_stepSize = (noiseVolume - oldNoiseVolume) / sampleCount;
    int   sampleNum = 0;
    for (uint32_t s=0; s<channelCount*sampleCount; s++) {
        float tgtVol = oldNoiseVolume + sampleNum * interpolate_stepSize;
        float noise = GeneratePinkNoise( &fgcom_PinkSource );
        noise = noise * tgtVol;
        outputPCM[s] = outputPCM[s] + noise;

        sampleNum++;
    }
}


void fgcom_audio_applyVolume(float oldVolume, float volume, float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
    // just loop over the array, applying the interpolated volume
    if (volume == 1.0) return; // no adjustment requested

    float interpolate_stepSize = (volume - oldVolume) / sampleCount;
    int   sampleNum = 0;
    // TODO: Make sure we are not going off limits
    for (uint32_t s=0; s<channelCount*sampleCount; s++) {
        float tgtVol = oldVolume + sampleNum * interpolate_stepSize;
        outputPCM[s] = outputPCM[s] * tgtVol;

        sampleNum++;
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
    
    // Ok, first some assupmtions to save runtime:
    //  - we are assuming a mono stream, ie. all channels contain the same float values already!
    //  - therefore we need just to use the first channels data.
    //  - if this is not true, we will overwrite all subsequent channels with the first ones filtered values.
    
    /*
     * Prepare a DSP data buffer and populate it with the first channels values
     */
    float* audioData[1];
    audioData[0] = new float[sampleCount];
    // Loop over the samples of channel=0 and copy it to the DSP audio buffer
    uint32_t ai = 0;
    for (uint32_t s=0; s<channelCount*sampleCount; s+=channelCount) {
        audioData[0][ai] = outputPCM[s];
        ai++;
    }

    
    /*
     * Apply filtering
     */
    
    // Human speak frequencies range roughly from about 300Hz to 5000Hz.
    // Playing with audacitys filter courve effect allows for testing results.
    
    // HighPass filter cuts away lower frequency ranges and let higher ones pass
    if (highpass_cutoff > 0 ) {
        Dsp::Params f_highpass_p;
        f_highpass_p[0] = sampleRateHz; // sample rate
        f_highpass_p[1] = highpass_cutoff; // cutoff frequency
        f_highpass_p[2] = 2.0; // Q
        f_highpass->setParams (f_highpass_p);
        f_highpass->process (sampleCount, audioData);
    }

    // LowPass filter cuts away higher frequency ranges and lets lower ones pass
    if (lowpass_cutoff > 0 ) {
        Dsp::Params f_lowpass_p;
        f_lowpass_p[0] = sampleRateHz; // sample rate
        f_lowpass_p[1] = lowpass_cutoff; // cutoff frequency
        f_lowpass_p[2] = 0.97; // Q
        f_lowpass->setParams (f_lowpass_p);
        f_lowpass->process (sampleCount, audioData);
    }
    
    /*
     * Apply filtered result to all channels (treats audio as mono!)
     */
    ai = 0;
    for (uint32_t s=0; s<channelCount*sampleCount; s+=channelCount) { // each sample of channel=0
        for (uint32_t c=0; c<channelCount; c++) {
            outputPCM[s+c] = audioData[0][ai];
        }
        ai++;
    }
    
}
