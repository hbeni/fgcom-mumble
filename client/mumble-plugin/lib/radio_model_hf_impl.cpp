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
#include "propagation_physics.h"
#include <cmath>

// Static member is defined in the original radio_model_hf.cpp file

// Constructor and destructor are defined in header

// Calculate power distance
float FGCom_radiowaveModel_HF::calcPowerDistance(float power, double slantDist) {
    // HF propagation model using ITU-R formulas
    if (power <= 0.0 || slantDist <= 0.0) {
        return 0.0f;
    }
    
    // Get power management instance
    auto& power_manager = FGCom_PowerManager::getInstance();
    
    // Calculate effective radiated power considering efficiency
    float effective_power = power * power_manager.getCurrentPowerEfficiency();
    
    // If power efficiency is 0, use power directly (fallback)
    if (effective_power <= 0.0f) {
        effective_power = power;
    }
    
    // Convert power to dBm for ITU-R calculations
    double tx_power_dbm = 10.0 * log10(effective_power * 1000.0);
    double rx_sensitivity_dbm = -120.0; // Typical receiver sensitivity
    double frequency_mhz = 15.0; // Default HF frequency
    double altitude_m = 0.0; // HF uses slant distance, altitude handled separately
    
    // Use ITU-R formulas from propagation_physics.cpp
    // Note: HF uses slant distance which already accounts for altitude
    double total_loss_db = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        frequency_mhz,
        slantDist,
        altitude_m,
        altitude_m,  // Using same altitude for both TX and RX
        tx_power_dbm,
        rx_sensitivity_dbm,
        0.0,  // Additional atmospheric loss
        0.0   // Terrain loss
    );
    
    // Add ionospheric effects for HF (skywave propagation)
    double ionospheric_loss = 10.0 * log10(slantDist);
    total_loss_db += ionospheric_loss;
    
    // Calculate received power in dBm
    double rx_power_dbm = tx_power_dbm - total_loss_db;
    
    // Convert received power to linear scale (watts)
    double rx_power_watts = pow(10.0, (rx_power_dbm - 30.0) / 10.0);
    
    // Convert to signal quality (0.0 to 1.0)
    // Signal quality based on received power using ITU-R reference levels
    // Use reference-based mapping: -120 dBm (minimum detectable) = 0.0, -50 dBm (excellent) = 1.0
    const double rx_power_ref_min = -120.0;  // dBm - minimum detectable signal
    const double rx_power_ref_max = -50.0;   // dBm - excellent signal quality
    
    float signal_quality;
    if (rx_power_dbm <= rx_power_ref_min) {
        signal_quality = 0.0f;
    } else if (rx_power_dbm >= rx_power_ref_max) {
        signal_quality = 1.0f;
    } else {
        // Linear interpolation between reference levels
        signal_quality = (float)((rx_power_dbm - rx_power_ref_min) / (rx_power_ref_max - rx_power_ref_min));
    }
    
    // Ensure quality is in valid range [0.0, 1.0]
    signal_quality = (float)std::min(1.0, std::max(0.0, (double)signal_quality));
    
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
    double height_above_horizon = heightAboveHorizon(dist, alt1, alt2);
    double slantDist = getSlantDistance(dist, height_above_horizon-alt1);
    
    // HF can work beyond line of sight via sky waves
    if (power <= 0.0f) {
        // No power - return 0.0 (HF uses 0.0 for no signal, not -1.0)
        signal.quality = 0.0f;
    } else if (dist > 0.0) {
        signal.quality = calcPowerDistance(power, slantDist);
        signal.direction = getDirection(lat1, lon1, lat2, lon2);
        signal.verticalAngle = degreeAboveHorizon(dist, alt2-alt1);
    }
    
    return signal;
}

// Check compatibility with other radio models
bool FGCom_radiowaveModel_HF::isCompatible(FGCom_radiowaveModel *otherModel) {
    return otherModel->getType() != "STRING";
}
