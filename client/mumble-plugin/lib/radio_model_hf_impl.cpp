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

#include "radio_model_hf.h"
#include "audio.h"
#include "solar_data.h"
#include "power_management.h"

// Static member is defined in the original radio_model_hf.cpp file

// Constructor and destructor are defined in header

// Calculate power distance
float FGCom_radiowaveModel_HF::calcPowerDistance(float power, double slantDist) {
    // Get power management instance
    auto& power_manager = FGCom_PowerManager::getInstance();
    
    // Calculate effective radiated power considering efficiency
    float effective_power = power * power_manager.getCurrentPowerEfficiency();
    
    // HF propagation model
    if (power <= 0.0 || slantDist <= 0.0) {
        return 0.0f;
    }
    
    // Free space path loss for HF
    double wavelength = 300.0 / 15.0; // 15 MHz default
    double free_space_loss = 20.0 * log10(4.0 * M_PI * slantDist * 1000.0 / wavelength);
    
    // Ionospheric effects
    double ionospheric_loss = 10.0 * log10(slantDist);
    
    // Total path loss
    double total_loss_db = free_space_loss + ionospheric_loss;
    
    // Convert to linear scale
    double total_loss_linear = pow(10.0, -total_loss_db / 10.0);
    
    // Calculate received power
    double received_power_watts = effective_power * total_loss_linear;
    
    // Convert to signal quality (0.0 to 1.0)
    float signal_quality = (float)std::min(1.0, std::max(0.0, received_power_watts / effective_power));
    
    return signal_quality;
}

// Get type
std::string FGCom_radiowaveModel_HF::getType() {
    return "HF";
}

// Convert channel to frequency
std::string FGCom_radiowaveModel_HF::conv_chan2freq(std::string frq) {
    return frq; // Simplified
}

// Convert frequency to channel
std::string FGCom_radiowaveModel_HF::conv_freq2chan(std::string frq) {
    return frq; // Simplified
}

// Get frequency match
float FGCom_radiowaveModel_HF::getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
    float frq1_f = std::stof(r1.frequency);
    float frq2_f = std::stof(r2.frequency);
    
    float width_kHz = 3.0f; // HF channel width
    float channel_core = 1.5f; // HF channel core
    
    return getChannelAlignment(frq1_f, frq2_f, width_kHz, channel_core);
}

// Process audio samples
void FGCom_radiowaveModel_HF::processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
    // HF-specific audio processing
    fgcom_audio_makeMono(outputPCM, sampleCount, channelCount);
    fgcom_audio_filter(300, 3000, outputPCM, sampleCount, channelCount, sampleRateHz);
    fgcom_audio_applyVolume(lclRadio.volume, outputPCM, sampleCount, channelCount);
    
    // Add HF-specific noise
    float noise_level = 0.1f + (1.0f - signalQuality) * 0.3f;
    fgcom_audio_addNoise(noise_level, outputPCM, sampleCount, channelCount);
}

// Get signal
fgcom_radiowave_signal FGCom_radiowaveModel_HF::getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
    fgcom_radiowave_signal signal;
    signal.quality = 0.0f;
    signal.direction = 0.0f;
    signal.verticalAngle = 0.0f;
    
    // Calculate distance
    double dist = getSurfaceDistance(lat1, lon1, lat2, lon2);
    
    // HF can work beyond line of sight via sky waves
    if (dist > 0.0) {
        signal.quality = calcPowerDistance(power, dist);
        signal.direction = getDirection(lat1, lon1, lat2, lon2);
        signal.verticalAngle = degreeAboveHorizon(dist, alt2-alt1);
    }
    
    return signal;
}
