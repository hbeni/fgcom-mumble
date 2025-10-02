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
#include <iostream> 
#include <cmath>
#include <regex>
#include "radio_model_vhf.h"
#include "audio.h"

// Constructor
FGCom_radiowaveModel_VHF::FGCom_radiowaveModel_VHF() 
    : patterns_initialized(false), ducting_initialized(false), multipath_initialized(false) {
}

// Destructor
FGCom_radiowaveModel_VHF::~FGCom_radiowaveModel_VHF() {
}

// Initialize antenna patterns for VHF frequencies
void FGCom_radiowaveModel_VHF::initializePatterns() {
    if (patterns_initialized) return;
    
    pattern_interpolation = std::make_unique<FGCom_PatternInterpolation>();
    antenna_system = std::make_unique<FGCom_AntennaGroundSystem>();
    
    // Load VHF antenna patterns for common vehicles
    loadVHFAntennaPatterns();
    
    patterns_initialized = true;
}

// Initialize atmospheric ducting system
void FGCom_radiowaveModel_VHF::initializeDucting() {
    if (ducting_initialized) return;
    
    atmospheric_ducting = std::make_unique<FGCom_AtmosphericDucting>();
    atmospheric_ducting->setMinimumDuctingStrength(0.3f);
    atmospheric_ducting->setDuctingHeightRange(50.0f, 2000.0f);
    atmospheric_ducting->setTemperatureInversionThreshold(0.5f);
    
    ducting_initialized = true;
}

// Initialize enhanced multipath system
void FGCom_radiowaveModel_VHF::initializeMultipath() {
    if (multipath_initialized) return;
    
    enhanced_multipath = std::make_unique<FGCom_EnhancedMultipath>();
    enhanced_multipath->setTerrainRoughness(1.0f);
    enhanced_multipath->setBuildingDensity(0.1f);
    enhanced_multipath->setVegetationDensity(0.2f);
    enhanced_multipath->setVehicleDensity(0.05f);
    
    multipath_initialized = true;
}

// Load VHF antenna patterns for various vehicles
void FGCom_radiowaveModel_VHF::loadVHFAntennaPatterns() {
    // Aircraft VHF patterns
    loadAircraftVHFPatterns();
    
    // Ground vehicle VHF patterns  
    loadGroundVehicleVHFPatterns();
    
    // Maritime VHF patterns
    loadMaritimeVHFPatterns();
}

void FGCom_radiowaveModel_VHF::loadAircraftVHFPatterns() {
    // Use pattern mapping system to load all available aircraft patterns
    if (!g_antenna_pattern_mapping) {
        g_antenna_pattern_mapping = std::make_unique<FGCom_AntennaPatternMapping>();
    }
    
    // Load all available aircraft patterns dynamically
    std::vector<AntennaPatternInfo> aircraft_patterns = 
        g_antenna_pattern_mapping->getAvailableVHFPatterns("aircraft");
    
    for (const auto& pattern_info : aircraft_patterns) {
        if (pattern_interpolation->load4NEC2Pattern(
            pattern_info.pattern_file, 
            pattern_info.antenna_name, 0, pattern_info.frequency_mhz)) {
            std::cout << "Loaded aircraft VHF pattern: " << pattern_info.antenna_name << std::endl;
        }
    }
    
    // Load 3D attitude patterns for aircraft
    loadAircraft3DAttitudePatterns();
}

void FGCom_radiowaveModel_VHF::loadAircraft3DAttitudePatterns() {
    // Load 3D attitude patterns for key aircraft frequencies
    std::vector<double> aircraft_frequencies = {125.0, 144.0, 150.0, 160.0};
    std::vector<int> altitudes = {0, 1000, 3000, 5000, 10000};
    
    for (double freq : aircraft_frequencies) {
        for (int alt : altitudes) {
            std::vector<AntennaPatternInfo> attitude_patterns = 
                g_antenna_pattern_mapping->getAvailable3DPatterns("aircraft", freq, alt);
            
            for (const auto& pattern_info : attitude_patterns) {
                if (pattern_interpolation->load3DAttitudePattern(
                    pattern_info.pattern_file, 
                    pattern_info.antenna_name, 0, 0, 0, freq)) {
                    std::cout << "Loaded aircraft 3D attitude pattern: " << pattern_info.antenna_name << std::endl;
                }
            }
        }
    }
}

void FGCom_radiowaveModel_VHF::loadGroundVehicleVHFPatterns() {
    // Load all available ground vehicle patterns dynamically
    std::vector<AntennaPatternInfo> ground_patterns = 
        g_antenna_pattern_mapping->getAvailableVHFPatterns("ground_vehicle");
    
    for (const auto& pattern_info : ground_patterns) {
        if (pattern_interpolation->load4NEC2Pattern(
            pattern_info.pattern_file, 
            pattern_info.antenna_name, 0, pattern_info.frequency_mhz)) {
            std::cout << "Loaded ground vehicle VHF pattern: " << pattern_info.antenna_name << std::endl;
        }
    }
    
    // Load handheld patterns
    std::vector<AntennaPatternInfo> handheld_patterns = 
        g_antenna_pattern_mapping->getAvailableVHFPatterns("handheld");
    
    for (const auto& pattern_info : handheld_patterns) {
        if (pattern_interpolation->load4NEC2Pattern(
            pattern_info.pattern_file, 
            pattern_info.antenna_name, 0, pattern_info.frequency_mhz)) {
            std::cout << "Loaded handheld VHF pattern: " << pattern_info.antenna_name << std::endl;
        }
    }
    
    // Load base station patterns
    std::vector<AntennaPatternInfo> base_patterns = 
        g_antenna_pattern_mapping->getAvailableVHFPatterns("base_station");
    
    for (const auto& pattern_info : base_patterns) {
        if (pattern_interpolation->load4NEC2Pattern(
            pattern_info.pattern_file, 
            pattern_info.antenna_name, 0, pattern_info.frequency_mhz)) {
            std::cout << "Loaded base station VHF pattern: " << pattern_info.antenna_name << std::endl;
        }
    }
}

void FGCom_radiowaveModel_VHF::loadMaritimeVHFPatterns() {
    // Load all available maritime patterns dynamically
    std::vector<AntennaPatternInfo> maritime_patterns = 
        g_antenna_pattern_mapping->getAvailableVHFPatterns("maritime");
    
    for (const auto& pattern_info : maritime_patterns) {
        if (pattern_interpolation->load4NEC2Pattern(
            pattern_info.pattern_file, 
            pattern_info.antenna_name, 0, pattern_info.frequency_mhz)) {
            std::cout << "Loaded maritime VHF pattern: " << pattern_info.antenna_name << std::endl;
        }
    }
    
    // Load ship patterns
    std::vector<AntennaPatternInfo> ship_patterns = 
        g_antenna_pattern_mapping->getAvailableVHFPatterns("ship");
    
    for (const auto& pattern_info : ship_patterns) {
        if (pattern_interpolation->load4NEC2Pattern(
            pattern_info.pattern_file, 
            pattern_info.antenna_name, 0, pattern_info.frequency_mhz)) {
            std::cout << "Loaded ship VHF pattern: " << pattern_info.antenna_name << std::endl;
        }
    }
}

// Get antenna gain for VHF frequencies
float FGCom_radiowaveModel_VHF::getAntennaGain(const std::string& antenna_name, int frequency_mhz, 
                        double elevation_deg, double azimuth_deg, double altitude_m, 
                        int vehicle_type, int antenna_type) {
    if (!patterns_initialized) {
        initializePatterns();
    }
    
    if (!pattern_interpolation) {
        return 0.0f; // No pattern system available
    }
    
    // Check if we have 3D attitude patterns for this antenna
    if (pattern_interpolation->has3DAttitudePattern(antenna_name)) {
        // Use 3D attitude pattern for more accurate gain calculation
        return pattern_interpolation->get3DAttitudeGain(
            antenna_name, elevation_deg, azimuth_deg, frequency_mhz, 
            vehicle_type, antenna_type, altitude_m);
    }
    
    // Fall back to 2D pattern interpolation
    return pattern_interpolation->getInterpolatedGain(
        antenna_name, frequency_mhz, elevation_deg, azimuth_deg, altitude_m);
}

// Get available VHF patterns
std::vector<std::string> FGCom_radiowaveModel_VHF::getAvailableVHFPatterns() const {
    std::vector<std::string> patterns;
    if (g_antenna_pattern_mapping) {
        // Get all available patterns from the mapping system
        auto aircraft_patterns = g_antenna_pattern_mapping->getAvailableVHFPatterns("aircraft");
        auto ground_patterns = g_antenna_pattern_mapping->getAvailableVHFPatterns("ground_vehicle");
        auto maritime_patterns = g_antenna_pattern_mapping->getAvailableVHFPatterns("maritime");
        
        for (const auto& pattern : aircraft_patterns) {
            patterns.push_back(pattern.antenna_name);
        }
        for (const auto& pattern : ground_patterns) {
            patterns.push_back(pattern.antenna_name);
        }
        for (const auto& pattern : maritime_patterns) {
            patterns.push_back(pattern.antenna_name);
        }
    }
    return patterns;
}

// Check if pattern is available
bool FGCom_radiowaveModel_VHF::hasVHFPattern(const std::string& pattern_name) const {
    if (!g_antenna_pattern_mapping) return false;
    
    auto patterns = getAvailableVHFPatterns();
    return std::find(patterns.begin(), patterns.end(), pattern_name) != patterns.end();
}

// Override base class methods
void FGCom_radiowaveModel_VHF::processAudioSamples(fgcom_radio lclRadio, float signalQuality, 
                                   float* outputPCM, uint32_t sampleCount, 
                                   uint16_t channelCount, uint32_t sampleRateHz) {
    // HighPass filter cuts away lower frequency ranges and let higher ones pass
    // Lower cutoff limit depends on signal quality: the less quality, the more to cut away
    int highpass_cutoff = 3000 + (int)((1.0f - signalQuality) * 2000.0f);
    int lowpass_cutoff = 8000 + (int)(signalQuality * 4000.0f);
    
    // Process audio with VHF-specific characteristics
    processAudioSamples_VHF(highpass_cutoff, lowpass_cutoff, 0.05f, 0.45f, 
                           lclRadio, signalQuality, outputPCM, sampleCount, channelCount, sampleRateHz);
}

fgcom_radiowave_signal FGCom_radiowaveModel_VHF::getSignal(double lat1, double lon1, float alt1, 
                                                          double lat2, double lon2, float alt2, 
                                                          float power) {
    fgcom_radiowave_signal signal;
    signal.quality = 0.0f;
    signal.direction = 0.0f;
    signal.verticalAngle = 0.0f;
    
    // Calculate distance and line of sight
    double radiodist = getDistToHorizon(alt1) + getDistToHorizon(alt2);
    double dist = getSurfaceDistance(lat1, lon1, lat2, lon2);
    
    if (dist > radiodist) {
        // Beyond line of sight
        signal.quality = 0.0f;
        return signal;
    }
    
    double height_above_horizon = heightAboveHorizon(dist, alt1, alt2);
    double slantDist = getSlantDistance(dist, height_above_horizon-alt1);
    
    // Calculate signal strength
    float ss = calcPowerDistance(power, slantDist, alt1, 150.0);
    signal.quality = ss;
    
    // Calculate angles for antenna gain
    if (ss > 0.0f) {
        double theta_deg = degreeAboveHorizon(dist, alt2-alt1);  // Elevation angle
        double phi_deg = getDirection(lat1, lon1, lat2, lon2);   // Azimuth angle
        (void)theta_deg; // Suppress unused variable warning
        (void)phi_deg; // Suppress unused variable warning
        
        // Apply atmospheric ducting effects if initialized
        if (!ducting_initialized) {
            initializeDucting();
        }
        
        if (atmospheric_ducting) {
            DuctingConditions ducting = atmospheric_ducting->analyzeDuctingConditions(
                lat1, lon1, alt1, alt2);
            
            if (ducting.ducting_present) {
                DuctingCalculationParams ducting_params;
                ducting_params.frequency_hz = 150.0e6;
                ducting_params.distance_km = dist;
                ducting_params.tx_altitude_m = alt1;
                ducting_params.rx_altitude_m = alt2;
                
                float ducting_enhancement = atmospheric_ducting->calculateDuctingEffects(
                    ducting, ducting_params);
                signal.quality *= ducting_enhancement;
            }
        }
        
        // Apply enhanced multipath effects if initialized
        if (!multipath_initialized) {
            initializeMultipath();
        }
        
        if (enhanced_multipath) {
            MultipathCalculationParams multipath_params;
            multipath_params.frequency_hz = 150.0e6;
            multipath_params.distance_km = dist;
            multipath_params.tx_altitude_m = alt1;
            multipath_params.rx_altitude_m = alt2;
            multipath_params.terrain_roughness_m = 1.0f;
            multipath_params.building_density = 0.1f;
            multipath_params.vegetation_density = 0.2f;
            multipath_params.vehicle_density = 0.05f;
            
            MultipathChannel channel = enhanced_multipath->analyzeMultipathChannel(multipath_params);
            float multipath_quality = enhanced_multipath->calculateSignalQuality(channel, signal.quality);
            signal.quality = multipath_quality;
        }
    }
    
    // Set direction and vertical angle
    signal.direction     = getDirection(lat1, lon1, lat2, lon2);
    signal.verticalAngle = degreeAboveHorizon(dist, alt2-alt1);
    
    return signal;
}

float FGCom_radiowaveModel_VHF::calcPowerDistance(float power_watts, double distance_km, 
                                  double altitude_m, double frequency_mhz) {
    (void)altitude_m; // Suppress unused parameter warning
    // VHF propagation model with power and distance calculation
    if (power_watts <= 0.0 || distance_km <= 0.0) {
        return 0.0f;
    }
    
    // Free space path loss
    double wavelength = 300.0 / frequency_mhz; // Wavelength in meters
    double free_space_loss = 20.0 * log10(4.0 * M_PI * distance_km * 1000.0 / wavelength);
    
    // Atmospheric absorption (simplified)
    double atmospheric_loss = 0.01 * distance_km;
    
    // Total path loss
    double total_loss_db = free_space_loss + atmospheric_loss;
    
    // Convert to linear scale
    double total_loss_linear = pow(10.0, -total_loss_db / 10.0);
    
    // Calculate received power
    double received_power_watts = power_watts * total_loss_linear;
    
    // Convert to signal quality (0.0 to 1.0)
    float signal_quality = (float)std::min(1.0, std::max(0.0, received_power_watts / power_watts));
    
    return signal_quality;
}

// Required virtual methods from base class
std::string FGCom_radiowaveModel_VHF::getType() {
    return "VHF";
}

std::string FGCom_radiowaveModel_VHF::conv_chan2freq(std::string frq) {
    // VHF frequency conversion
    return frq; // Simplified - just return the input
}

std::string FGCom_radiowaveModel_VHF::conv_freq2chan(std::string frq) {
    // VHF channel conversion
    return frq; // Simplified - just return the input
}

float FGCom_radiowaveModel_VHF::getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
    // VHF frequency matching
    float frq1_f = std::stof(r1.frequency);
    float frq2_f = std::stof(r2.frequency);
    
    float width_kHz = 25.0f; // VHF channel width
    float channel_core = 12.5f; // VHF channel core
    
    float filter = getChannelAlignment(frq1_f, frq2_f, width_kHz, channel_core);
    
    return filter;
}

// VHF-specific audio processing
void FGCom_radiowaveModel_VHF::processAudioSamples_VHF(int highpass_cutoff, int lowpass_cutoff, 
                                                       float minimumNoiseVolume, float maximumNoiseVolume, 
                                                       fgcom_radio lclRadio, float signalQuality, 
                                                       float *outputPCM, uint32_t sampleCount, 
                                                       uint16_t channelCount, uint32_t sampleRateHz) {
    // Convert to mono if needed
    fgcom_audio_makeMono(outputPCM, sampleCount, channelCount);
    
    // Apply VHF-specific filtering
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
