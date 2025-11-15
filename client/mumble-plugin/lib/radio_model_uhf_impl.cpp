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

#include "radio_model_uhf.h"
#include "audio.h"
#include "pattern_interpolation.h"
#include "antenna_ground_system.h"
#include "antenna_pattern_mapping.h"
#include "propagation_physics.h"
#include <cmath>

// Constructor
FGCom_radiowaveModel_UHF::FGCom_radiowaveModel_UHF() 
    : uhf_patterns_initialized(false) {
    // Initialize UHF radio model
}

// Destructor
FGCom_radiowaveModel_UHF::~FGCom_radiowaveModel_UHF() {
}

// Initialize UHF patterns
void FGCom_radiowaveModel_UHF::initializeUHFPatterns() {
    if (uhf_patterns_initialized) return;
    
    uhf_pattern_interpolation = std::make_unique<FGCom_PatternInterpolation>();
    uhf_antenna_system = std::make_unique<FGCom_AntennaGroundSystem>();
    
    // Load UHF antenna patterns for common vehicles
    loadUHFAntennaPatterns();
    
    uhf_patterns_initialized = true;
}

// Load UHF antenna patterns
void FGCom_radiowaveModel_UHF::loadUHFAntennaPatterns() {
    // Load aircraft UHF patterns
    loadAircraftUHFPatterns();
    
    // Load ground vehicle UHF patterns
    loadGroundVehicleUHFPatterns();
    
    // Load maritime UHF patterns
    loadMaritimeUHFPatterns();
}

// Load aircraft UHF patterns
void FGCom_radiowaveModel_UHF::loadAircraftUHFPatterns() {
    // Simplified UHF pattern loading
    std::cout << "Loading aircraft UHF patterns" << std::endl;
}

// Load ground vehicle UHF patterns
void FGCom_radiowaveModel_UHF::loadGroundVehicleUHFPatterns() {
    // Simplified UHF pattern loading
    std::cout << "Loading ground vehicle UHF patterns" << std::endl;
}

// Load maritime UHF patterns
void FGCom_radiowaveModel_UHF::loadMaritimeUHFPatterns() {
    // Simplified UHF pattern loading
    std::cout << "Loading maritime UHF patterns" << std::endl;
}

// Get antenna gain
float FGCom_radiowaveModel_UHF::getAntennaGain(const std::string& antenna_name, int frequency_mhz, 
                        double elevation_deg, double azimuth_deg, double altitude_m, 
                        int vehicle_type, int antenna_type) {
    // Suppress unused parameter warnings
    (void)antenna_name;
    (void)frequency_mhz;
    (void)elevation_deg;
    (void)azimuth_deg;
    (void)altitude_m;
    (void)vehicle_type;
    (void)antenna_type;
    
    if (!uhf_patterns_initialized) {
        initializeUHFPatterns();
    }
    
    if (!uhf_pattern_interpolation) {
        return 0.0f; // No pattern system available
    }
    
    // Simplified UHF antenna gain calculation
    return 1.0f; // Default gain
}

// Get available UHF patterns
std::vector<std::string> FGCom_radiowaveModel_UHF::getAvailableUHFPatterns() const {
    std::vector<std::string> patterns;
    patterns.push_back("default_uhf");
    return patterns;
}

// Check if pattern is available
bool FGCom_radiowaveModel_UHF::hasUHFPattern(const std::string& pattern_name) const {
    return pattern_name == "default_uhf";
}

// Process audio samples
void FGCom_radiowaveModel_UHF::processAudioSamples(fgcom_radio lclRadio, float signalQuality, 
                                   float* outputPCM, uint32_t sampleCount, 
                                   uint16_t channelCount, uint32_t sampleRateHz) {
    // UHF-specific audio processing
    int highpass_cutoff = 3000 + (int)((1.0f - signalQuality) * 2000.0f);
    int lowpass_cutoff = 8000 + (int)(signalQuality * 4000.0f);
    
    processAudioSamples_UHF(highpass_cutoff, lowpass_cutoff, 0.05f, 0.45f, 
                           lclRadio, signalQuality, outputPCM, sampleCount, channelCount, sampleRateHz);
}

// Get signal
fgcom_radiowave_signal FGCom_radiowaveModel_UHF::getSignal(double lat1, double lon1, float alt1,
                          double lat2, double lon2, float alt2, float power) {
    fgcom_radiowave_signal signal;
    signal.quality = 0.0f;
    signal.direction = 0.0f;
    signal.verticalAngle = 0.0f;
    
    // Calculate distance and line of sight
    double radiodist = getDistToHorizon(alt1) + getDistToHorizon(alt2);
    double dist = getSurfaceDistance(lat1, lon1, lat2, lon2);
    
    if (dist > radiodist) {
        // Beyond line of sight - return -1.0 to indicate no signal
        signal.quality = -1.0f;
        return signal;
    }
    
    double height_above_horizon = heightAboveHorizon(dist, alt1, alt2);
    double slantDist = getSlantDistance(dist, height_above_horizon-alt1);
    
    // Calculate signal strength
    if (power <= 0.0f) {
        // No power - return -1.0 to indicate no signal
        signal.quality = -1.0f;
    } else {
        float ss = calcPowerDistance(power, slantDist, (alt1 + alt2) / 2.0, 400.0);
        signal.quality = ss;
    }
    
    // Set direction and vertical angle
    signal.direction     = getDirection(lat1, lon1, lat2, lon2);
    signal.verticalAngle = degreeAboveHorizon(dist, alt2-alt1);
    
    return signal;
}

// Calculate power distance
float FGCom_radiowaveModel_UHF::calcPowerDistance(float power_watts, double distance_km, 
                                  double altitude_m, double frequency_mhz) {
    // UHF propagation model using ITU-R formulas
    if (power_watts <= 0.0 || distance_km <= 0.0) {
        return 0.0f;
    }
    
    // Convert power to dBm for ITU-R calculations
    double tx_power_dbm = 10.0 * log10(power_watts * 1000.0);
    double rx_sensitivity_dbm = -120.0; // Typical receiver sensitivity
    
    // Use ITU-R formulas from propagation_physics.cpp
    double total_loss_db = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        frequency_mhz,
        distance_km,
        altitude_m,
        altitude_m,  // Using same altitude for both TX and RX
        tx_power_dbm,
        rx_sensitivity_dbm,
        0.0,  // Additional atmospheric loss
        0.0   // Terrain loss
    );
    
    // Calculate received power in dBm
    double rx_power_dbm = tx_power_dbm - total_loss_db;
    
    // Convert received power to linear scale (watts)
    double rx_power_watts = pow(10.0, (rx_power_dbm - 30.0) / 10.0);
    
    // Convert to signal quality (0.0 to 1.0)
    // Signal quality based on received power relative to transmitted power
    double power_ratio = rx_power_watts / power_watts;
    
    // Map power ratio to quality using a reasonable function
    float signal_quality;
    if (power_ratio <= 0.0) {
        signal_quality = 0.0f;
    } else {
        // Use log10 mapping with scaling
        double log_ratio = log10(power_ratio);
        // Normalize: -10 dB (0.1 ratio) -> ~0.5 quality, 0 dB (1.0 ratio) -> 1.0 quality
        signal_quality = (float)std::min(1.0, std::max(0.0, 1.0 + log_ratio / 10.0));
    }
    
    // Ensure quality is in valid range [0.0, 1.0]
    signal_quality = (float)std::min(1.0, std::max(0.0, (double)signal_quality));
    
    return signal_quality;
}

// Get type
std::string FGCom_radiowaveModel_UHF::getType() {
    return "UHF";
}

// Convert channel to frequency
std::string FGCom_radiowaveModel_UHF::conv_chan2freq(std::string frq) {
    return frq; // Simplified
}

// Convert frequency to channel
std::string FGCom_radiowaveModel_UHF::conv_freq2chan(std::string frq) {
    return frq; // Simplified
}

// Get frequency match
float FGCom_radiowaveModel_UHF::getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
    float frq1_f = std::stof(r1.frequency);
    float frq2_f = std::stof(r2.frequency);
    
    float width_kHz = 25.0f; // UHF channel width
    float channel_core = 12.5f; // UHF channel core
    
    return getChannelAlignment(frq1_f, frq2_f, width_kHz, channel_core);
}

// UHF-specific audio processing
void FGCom_radiowaveModel_UHF::processAudioSamples_UHF(int highpass_cutoff, int lowpass_cutoff, 
                                float minimumNoiseVolume, float maximumNoiseVolume, 
                                fgcom_radio lclRadio, float signalQuality, 
                                float *outputPCM, uint32_t sampleCount, 
                                uint16_t channelCount, uint32_t sampleRateHz) {
    // Convert to mono if needed
    fgcom_audio_makeMono(outputPCM, sampleCount, channelCount);
    
    // Apply UHF-specific filtering
    fgcom_audio_filter(highpass_cutoff, lowpass_cutoff, outputPCM, sampleCount, channelCount, sampleRateHz);
    
    // Apply volume control
    fgcom_audio_applyVolume(lclRadio.volume, outputPCM, sampleCount, channelCount);
    
    // Add noise based on signal quality
    float noise_level = minimumNoiseVolume + (1.0f - signalQuality) * (maximumNoiseVolume - minimumNoiseVolume);
    fgcom_audio_addNoise(noise_level, outputPCM, sampleCount, channelCount);
    
    // Apply signal quality degradation
    fgcom_audio_applySignalQualityDegradation(outputPCM, sampleCount, channelCount, signalQuality);
    
    // Final volume adjustment
    fgcom_audio_applyVolume(signalQuality, outputPCM, sampleCount, channelCount);
}
