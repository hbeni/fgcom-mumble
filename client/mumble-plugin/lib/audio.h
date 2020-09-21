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
#ifndef FGCOM_AUDIO_H
#define FGCOM_AUDIO_H
#include "mumble/PluginComponents_v_1_0_x.h"

/*
 * Add static noise to the signal
 * 
 * @param float signalQuality 0.0 to 1.0 for signal quality
 */
void fgcom_audio_addNoise(float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount);


/*
 * Apply volume modificator to samples
 * 
 * @param float volume: <1.0 make quieter, >1.0 boost
 */
void fgcom_audio_applyVolume(float volume, float *outputPCM, uint32_t sampleCount, uint16_t channelCount);


/*
 * Make the audio mono
 */
void fgcom_audio_makeMono(float *outputPCM, uint32_t sampleCount, uint16_t channelCount);


/*
 * Apply audio filter
 */
void fgcom_audio_filter(float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz);

#endif
