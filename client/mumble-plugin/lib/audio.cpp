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
#include <iostream>  // cout
 
/*
 * This file contains audio processing stuff.
 * We use the DSPFilter library for filtering/adjusting the audio samples.
 * The code is heavily inspired from the GPL'ed IDI-Systems Arma3 ACRE TS
 * plugin to be found at https://github.com/IDI-Systems/acre2
 * Thank you NouberNou and friends, i have no clue on audio processing and
 * and this would not have been possible without your code!
 */

void fgcom_audio_applyVolume(float volume, float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
    // just loop over the array, applying the volume
    std::cout << "DBG: adjusted volume by " << volume << std::endl;
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
