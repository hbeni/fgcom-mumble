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
#include "frequency_offset.h"

/*
 * Add static noise to the signal
 * 
 * @param float noiseVolume 0.0 to 1.0 for normalized volume
 */
void fgcom_audio_addNoise(float noiseVolume, float *outputPCM, uint32_t sampleCount, uint16_t channelCount);

/*
 * Apply signal quality degradation for poor signal conditions
 * 
 * @param float* outputPCM Audio buffer to process
 * @param uint32_t sampleCount Number of samples
 * @param uint16_t channelCount Number of channels
 * @param float dropoutProbability Probability of audio dropout (0.0 to 1.0)
 */
void fgcom_audio_applySignalQualityDegradation(float *outputPCM, uint32_t sampleCount, uint16_t channelCount, float dropoutProbability);


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
 * 
 * If highpass_cutoff / lowpass_cutoff == 0, then the respective filter is skipped
 */
void fgcom_audio_filter(int highpass_cutoff, int lowpass_cutoff, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz);

/*
 * Apply frequency offset (Donald Duck Effect) using complex exponential method
 * 
 * @param float offset_hz: Frequency offset in Hz (positive = higher pitch, negative = lower pitch)
 * @param float *outputPCM: Audio buffer to process
 * @param uint32_t sampleCount: Number of samples
 * @param uint16_t channelCount: Number of channels
 * @param uint32_t sampleRateHz: Sample rate in Hz
 */
void fgcom_audio_applyFrequencyOffset(float offset_hz, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz);

/*
 * Apply Donald Duck effect (frequency shift up)
 * 
 * @param float intensity: Effect intensity (0.0-1.0)
 * @param float *outputPCM: Audio buffer to process
 * @param uint32_t sampleCount: Number of samples
 * @param uint16_t channelCount: Number of channels
 * @param uint32_t sampleRateHz: Sample rate in Hz
 */
void fgcom_audio_applyDonaldDuckEffect(float intensity, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz);

/*
 * Apply Doppler shift effect
 * 
 * @param float relative_velocity_mps: Relative velocity in m/s
 * @param float carrier_frequency_hz: Carrier frequency in Hz
 * @param float *outputPCM: Audio buffer to process
 * @param uint32_t sampleCount: Number of samples
 * @param uint16_t channelCount: Number of channels
 * @param uint32_t sampleRateHz: Sample rate in Hz
 */
void fgcom_audio_applyDopplerShift(float relative_velocity_mps, float carrier_frequency_hz, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz);

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
bool fgcom_audio_addSquelchNoise(float *outputPCM, uint32_t sampleCount, uint16_t channelCount, bool useLocationBasedNoise);

#endif
