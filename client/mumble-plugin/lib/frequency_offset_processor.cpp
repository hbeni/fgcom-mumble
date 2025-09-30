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

#include "frequency_offset.h"
#include <iostream>
#include <cmath>

// Static member definitions
std::unique_ptr<FGCom_FrequencyOffsetProcessor> FGCom_FrequencyOffsetProcessor::instance = nullptr;
std::mutex FGCom_FrequencyOffsetProcessor::instance_mutex;

// Constructor
FGCom_FrequencyOffsetProcessor::FGCom_FrequencyOffsetProcessor() 
    : config(), doppler_params() {
}

// Destructor is defined in header

// Get singleton instance
FGCom_FrequencyOffsetProcessor& FGCom_FrequencyOffsetProcessor::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (instance == nullptr) {
        instance = std::unique_ptr<FGCom_FrequencyOffsetProcessor>(new FGCom_FrequencyOffsetProcessor());
    }
    return *instance;
}

// Get configuration
FrequencyOffsetConfig FGCom_FrequencyOffsetProcessor::getConfig() const {
    return config;
}

// Set configuration
void FGCom_FrequencyOffsetProcessor::setConfig(const FrequencyOffsetConfig& new_config) {
    config = new_config;
}

// Set Doppler parameters
void FGCom_FrequencyOffsetProcessor::setDopplerParams(const DopplerShiftParams& params) {
    doppler_params = params;
}

// Apply frequency offset
bool FGCom_FrequencyOffsetProcessor::applyFrequencyOffset(float* audio_buffer, size_t samples, float offset_hz) {
    if (!config.enable_frequency_offset || samples == 0) {
        return false;
    }
    
    // Simple frequency offset implementation
    for (size_t i = 0; i < samples; ++i) {
        float phase = 2.0f * M_PI * offset_hz * i / config.sample_rate;
        audio_buffer[i] *= std::cos(phase);
    }
    return true;
}

// Apply Doppler shift
bool FGCom_FrequencyOffsetProcessor::applyDopplerShift(float* audio_buffer, size_t samples, const DopplerShiftParams& params) {
    if (!config.enable_doppler_shift || samples == 0) {
        return false;
    }
    
    // Simple Doppler shift implementation
    float doppler_factor = params.relative_velocity_mps / 343.0f; // Speed of sound
    float frequency_shift = params.carrier_frequency_hz * doppler_factor;
    
    for (size_t i = 0; i < samples; ++i) {
        float phase = 2.0f * M_PI * frequency_shift * i / config.sample_rate;
        audio_buffer[i] *= std::cos(phase);
    }
    return true;
}
