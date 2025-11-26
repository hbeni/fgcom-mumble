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

#include "radio_model_amateur.h"
#include "amateur_radio.h"
#include "audio/audio.h"
#include "propagation/weather/solar_data.h"

// Static member is defined in the original radio_model_amateur.cpp file

// Constructor
FGCom_radiowaveModel_Amateur::FGCom_radiowaveModel_Amateur(int region) : itu_region(region) {
    // Initialize amateur radio data
    FGCom_AmateurRadio::initialize();
}

// Destructor is defined in header

// Get type
std::string FGCom_radiowaveModel_Amateur::getType() {
    return "AMATEUR";
}

// Check compatibility
bool FGCom_radiowaveModel_Amateur::isCompatible(FGCom_radiowaveModel *otherModel) {
    return otherModel->getType() == "AMATEUR" || otherModel->getType() == "HF";
}

// Get signal with amateur radio characteristics
fgcom_radiowave_signal FGCom_radiowaveModel_Amateur::getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
    fgcom_radiowave_signal signal;
    signal.quality = 0.0f;
    signal.direction = 0.0f;
    signal.verticalAngle = 0.0f;
    
    // Calculate distance
    double dist = getSurfaceDistance(lat1, lon1, lat2, lon2);
    
    // Amateur radio propagation
    if (dist > 0.0) {
        // Use solar conditions for amateur radio
        float solar_factor = 0.5f; // Simplified solar factor
        
        // Calculate signal quality based on solar conditions
        signal.quality = std::min(1.0f, power / 100.0f * solar_factor);
        signal.direction = getDirection(lat1, lon1, lat2, lon2);
        signal.verticalAngle = degreeAboveHorizon(dist, alt2-alt1);
    }
    
    return signal;
}

// Convert channel to frequency
std::string FGCom_radiowaveModel_Amateur::conv_chan2freq(std::string frq) {
    return frq; // Simplified
}

// Convert frequency to channel
std::string FGCom_radiowaveModel_Amateur::conv_freq2chan(std::string frq) {
    return frq; // Simplified
}

// Get frequency match
float FGCom_radiowaveModel_Amateur::getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
    float frq1_f = std::stof(r1.frequency);
    float frq2_f = std::stof(r2.frequency);
    
    float width_kHz = 2.7f; // Amateur radio channel width
    float channel_core = 1.35f; // Amateur radio channel core
    
    return getChannelAlignment(frq1_f, frq2_f, width_kHz, channel_core);
}

// Process audio samples
void FGCom_radiowaveModel_Amateur::processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
    // Amateur radio specific audio processing
    fgcom_audio_makeMono(outputPCM, sampleCount, channelCount);
    fgcom_audio_filter(300, 3000, outputPCM, sampleCount, channelCount, sampleRateHz);
    fgcom_audio_applyVolume(lclRadio.volume, outputPCM, sampleCount, channelCount);
    
    // Add amateur radio specific noise
    float noise_level = 0.05f + (1.0f - signalQuality) * 0.2f;
    fgcom_audio_addNoise(noise_level, outputPCM, sampleCount, channelCount);
}
