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
#include "phil_burk_19990905_patest_pink.c"  // pink noise generator from  Phil Burk, http://www.softsynth.com

// DSP Filter framework; i want it statically in audio.o without adjusting makefile (so we can swap easily later if needed)
#include "DspFilters/Dsp.h"
#include "DspFilters/Param.cpp"
#include "DspFilters/Design.cpp"
#include "DspFilters/Filter.cpp"
#include "DspFilters/State.cpp"
#include "DspFilters/RootFinder.cpp"
#include "DspFilters/RBJ.cpp"
#include "DspFilters/Biquad.cpp"

 
/*
 * This file contains audio processing stuff.
 */


/**
 * Following functions are called from plugin code
 */
void fgcom_audio_addNoise(float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {

    // Calculate volume levels:
    // We want the noise to get louder at bad signal quality and the signal to get weaker.
    // basicly the signal quality already tells us how the ratio is between signal and noise.
    float signalVolume;
    float noiseVolume;
    float minimumNoiseVolume = 0.15;
    signalVolume = signalQuality;
    noiseVolume  = 1-signalQuality;
    if (noiseVolume < minimumNoiseVolume)  noiseVolume = minimumNoiseVolume;
    
    // Now tune down the signal according to calculated volume level
    fgcom_audio_applyVolume(signalVolume, outputPCM, sampleCount, channelCount);
    
    // TODO: we may clip some random samples from the signal on low quality
    
    // Apply noise to the signal
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
    // TODO: Make sure we are not going off limits
    for (uint32_t s=0; s<channelCount*sampleCount; s++) {
         outputPCM[s] = outputPCM[s] * volume;
    }
}


void fgcom_audio_makeMono(float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
    if (channelCount == 1) return; // no need to convert ono to mono!
    
    unsigned long sizeOfStream = channelCount*sampleCount;
 
    // loop over every set of samples for each channel
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


void fgcom_audio_filter(float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
    
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
    // numer in parenthesis after new... is the number of samples over which to fade parameter changes
    int sampleRateHz = 48000; // currently fixed at 48kHz (may be supplied from the API some day)
    
    Dsp::Filter* f_lowpass = new Dsp::SmoothedFilterDesign <Dsp::RBJ::Design::LowPass, 1> (1024);
    Dsp::Params f_lowpass_p;
    f_lowpass_p[0] = sampleRateHz; // sample rate
    f_lowpass_p[1] = 4000; // cutoff frequency
    f_lowpass_p[2] = 2.0; // Q
    f_lowpass->setParams (f_lowpass_p);
    f_lowpass->process (sampleCount, audioData);
    
    Dsp::Filter* f_highpass = new Dsp::SmoothedFilterDesign <Dsp::RBJ::Design::LowPass, 1> (1024);
    Dsp::Params f_highpass_p;
    f_highpass_p[0] = sampleRateHz; // sample rate
    f_highpass_p[1] = 750; // cutoff frequency
    f_highpass_p[2] = 0.97; // Q
    f_highpass->setParams (f_highpass_p);
    f_highpass->process (sampleCount, audioData);
    
    
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
