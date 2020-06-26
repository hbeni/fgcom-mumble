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

 
/*
 * This file contains audio processing stuff.
 */


/**
 * Following functions are called from plugin code
 */
void fgcom_audio_addNoise(float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {

    // Calculate volume levels:
    // We want the noise to get louder at bad signal quality and the signal to get weaker.
    float signalVolume;
    float noiseVolume;
    if (signalQuality >= 0.85) {
        noiseVolume  = 0.15; // let noise be constant from here on
        signalVolume = 1.0;
    } else {
        noiseVolume  = 1 - signalQuality;
        signalVolume = -1* pow(1 - signalQuality -0.15, 2) + 1;
    }
    
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
