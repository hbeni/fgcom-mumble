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
#include "radio_model.h"
#include "audio.h"
#include "pattern_interpolation.h"
#include "antenna_ground_system.h"
#include "antenna_pattern_mapping.h"
#include "propagation_physics.h"

/**
 * A UHF based radio model for the FGCom-mumble plugin.
 *
 * The model implements basic line-of-sight characteristics (between 300 and 3000 MHz).
 */
class FGCom_radiowaveModel_UHF : public FGCom_radiowaveModel {
private:
    // UHF-specific antenna pattern system
    std::unique_ptr<FGCom_PatternInterpolation> uhf_pattern_interpolation;
    std::unique_ptr<FGCom_AntennaGroundSystem> uhf_antenna_system;
    bool uhf_patterns_initialized;
    
    // Initialize UHF antenna patterns
    void initializeUHFPatterns() {
        if (uhf_patterns_initialized) return;
        
        uhf_pattern_interpolation = std::make_unique<FGCom_PatternInterpolation>();
        uhf_antenna_system = std::make_unique<FGCom_AntennaGroundSystem>();
        
        // Load UHF antenna patterns for common vehicles
        loadUHFAntennaPatterns();
        
        uhf_patterns_initialized = true;
    }
    
    // Load UHF antenna patterns for various vehicles
    void loadUHFAntennaPatterns() {
        // Military UHF patterns
        loadMilitaryUHFPatterns();
        
        // Civilian UHF patterns
        loadCivilianUHFPatterns();
    }
    
    void loadMilitaryUHFPatterns() {
        // Use pattern mapping system to load all available UHF patterns
        if (!g_antenna_pattern_mapping) {
            g_antenna_pattern_mapping = std::make_unique<FGCom_AntennaPatternMapping>();
        }
        
        // Load all available UHF patterns dynamically
        std::vector<AntennaPatternInfo> uhf_patterns = 
            g_antenna_pattern_mapping->getAvailableUHFPatterns("ground_station");
        
        for (const auto& pattern_info : uhf_patterns) {
            if (uhf_pattern_interpolation->load4NEC2Pattern(
                pattern_info.pattern_file, 
                pattern_info.antenna_name, 0, pattern_info.frequency_mhz)) {
                std::cout << "Loaded UHF pattern: " << pattern_info.antenna_name << std::endl;
            }
        }
    }
    
    void loadCivilianUHFPatterns() {
        // Load default UHF patterns for civilian use
        std::vector<AntennaPatternInfo> default_patterns = 
            g_antenna_pattern_mapping->getAvailableUHFPatterns("default");
        
        for (const auto& pattern_info : default_patterns) {
            if (uhf_pattern_interpolation->load4NEC2Pattern(
                pattern_info.pattern_file, 
                pattern_info.antenna_name, 0, pattern_info.frequency_mhz)) {
                std::cout << "Loaded civilian UHF pattern: " << pattern_info.antenna_name << std::endl;
            }
        }
    }
    
    // Get UHF antenna gain from pattern interpolation
    double getUHFGain(const std::string& antenna_name, int altitude_m, 
                     double frequency_mhz, double theta_deg, double phi_deg) {
        if (!uhf_patterns_initialized) {
            initializeUHFPatterns();
        }
        
        if (!uhf_pattern_interpolation) {
            return 0.0; // No pattern data available
        }
        
        return uhf_pattern_interpolation->getInterpolatedGain(
            antenna_name, altitude_m, frequency_mhz, theta_deg, phi_deg);
    }
    
    // Determine UHF antenna name based on vehicle type and frequency using pattern mapping
    std::string getUHFAntennaName(const std::string& vehicle_type, double frequency_mhz) {
        if (!g_antenna_pattern_mapping) {
            g_antenna_pattern_mapping = std::make_unique<FGCom_AntennaPatternMapping>();
        }
        
        // Use pattern mapping system to get appropriate UHF antenna
        AntennaPatternInfo pattern_info = g_antenna_pattern_mapping->getUHFPattern(vehicle_type, frequency_mhz);
        
        if (!pattern_info.antenna_name.empty()) {
            return pattern_info.antenna_name;
        }
        
        // Fallback to closest pattern
        pattern_info = g_antenna_pattern_mapping->getClosestUHFPattern(vehicle_type, frequency_mhz);
        if (!pattern_info.antenna_name.empty()) {
            return pattern_info.antenna_name;
        }
        
        // Default UHF antenna for unknown vehicle types
        return "default_uhf";
    }

protected:
    
    /*
    * Calculate the signal quality using realistic UHF propagation physics
    * 
    * NEW: Implements proper physics-based propagation modeling including:
    * - Free space path loss with frequency dependency
    * - Atmospheric absorption effects (more significant at UHF)
    * - Rain attenuation effects
    * - Antenna height gain
    * - Terrain obstruction effects
    * 
    * @param power in Watts
    * @param slantDist slant distance in km
    * @param frequency_mhz frequency in MHz
    * @param altitude_m altitude in meters
    * @param antenna_height_m antenna height in meters
    * @return float with the signal quality for given power and distance
    */
    virtual float calcPowerDistance(float power, double slantDist, double frequency_mhz = 400.0, 
                                   double altitude_m = 1000.0, double antenna_height_m = 10.0) {
        if (power <= 0.0 || slantDist <= 0.0) {
            return 0.0;
        }
        
        // Get atmospheric conditions (simplified - in production would use weather data)
        auto conditions = FGCom_PropagationPhysics::getAtmosphericConditions(0.0, 0.0, altitude_m);
        
        // Calculate total propagation loss using physics-based model
        double total_loss_db = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
            slantDist, frequency_mhz, altitude_m, antenna_height_m,
            conditions.temperature_c, conditions.humidity_percent,
            conditions.rain_rate_mmh, 0.0  // No terrain obstruction for now
        );
        
        // Calculate power-based signal quality
        // Convert power to dBm for calculation
        double power_dbm = 10.0 * log10(power * 1000.0);  // Convert watts to dBm
        
        // Calculate received power in dBm
        double received_power_dbm = power_dbm - total_loss_db;
        
        // Normalize signal quality (0.0 to 1.0)
        // UHF receivers typically have better sensitivity than VHF
        double sensitivity_dbm = -110.0;  // Better sensitivity at UHF
        double max_signal_dbm = 0.0;  // 0 dBm is very strong signal
        
        double signal_quality = std::max(0.0, std::min(1.0, 
            (received_power_dbm - sensitivity_dbm) / (max_signal_dbm - sensitivity_dbm)));
        
        return static_cast<float>(signal_quality);
    }
    
    // Legacy method for backward compatibility
    virtual float calcPowerDistance(float power, double slantDist) {
        return calcPowerDistance(power, slantDist, 400.0, 1000.0, 10.0);
    }
    
    
public:
    // Constructor
    FGCom_radiowaveModel_UHF() : uhf_patterns_initialized(false) {
        // UHF patterns will be loaded on first use
    }
    
    // Destructor
    ~FGCom_radiowaveModel_UHF() = default;
        
    std::string getType() {  return "UHF";  }
    
    bool isCompatible(FGCom_radiowaveModel *otherModel) {
        return otherModel->getType() != "STRING";
    }
    
    // Process audio samples for UHF
    virtual void processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
        // UHF audio processing - similar to VHF but with UHF-specific characteristics
        processAudioSamples_UHF(8000, 12000, 0.1f, 0.8f, lclRadio, signalQuality, outputPCM, sampleCount, channelCount, sampleRateHz);
    }
    
    // UHF-specific audio processing
    void processAudioSamples_UHF(int highpass_cutoff, int lowpass_cutoff, float minimumNoiseVolume, float maximumNoiseVolume, fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
        // UHF has higher frequency characteristics than VHF
        // Apply appropriate filtering and noise characteristics
        
        float noiseVolume;
        float signalVolume;
        
        // Calculate noise and signal volumes based on signal quality
        if (signalQuality > 0.8f) {
            // Strong signal - minimal noise
            noiseVolume = minimumNoiseVolume;
            signalVolume = 1.0f;
        } else if (signalQuality > 0.3f) {
            // Moderate signal - some noise
            noiseVolume = minimumNoiseVolume + (maximumNoiseVolume - minimumNoiseVolume) * (0.8f - signalQuality) * 0.5f;
            signalVolume = signalQuality;
        } else {
            // Weak signal - high noise
            noiseVolume = maximumNoiseVolume;
            signalVolume = signalQuality * 0.5f; // Reduce signal volume for weak signals
        }
        
        // Apply UHF-specific audio processing
        for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
            // Apply signal volume
            outputPCM[i] *= signalVolume;
            
            // Add UHF-specific noise characteristics
            if (noiseVolume > 0.0f) {
                float noise = ((float)rand() / RAND_MAX) * 2.0f - 1.0f; // -1 to 1
                outputPCM[i] += noise * noiseVolume;
            }
        }
    }

    // Override getSignal to use UHF-specific antenna patterns
    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
        struct fgcom_radiowave_signal signal;
    
        // get distance to radio horizon (that is the both ranges combined)
        double radiodist = this->getDistToHorizon(alt1) + this->getDistToHorizon(alt2);
        
        // get surface distance
        double dist = this->getSurfaceDistance(lat1, lon1, lat2, lon2);
        
        // get if they can see each other. UHF will have no connection when no line-of-sight is present.
        double heightAboveHorizon = this->heightAboveHorizon(dist, alt1, alt2);
        if (heightAboveHorizon < 0) return signal;  // no, they cant, bail out without signal.

        // get slant distance (in km) so we can calculate signal strenght based on distance
        double slantDist = this->getSlantDistance(dist, heightAboveHorizon-alt1);
        
        // apply physics-based power/distance model with frequency and altitude
        double frequency_mhz = 400.0;  // Default UHF frequency - could be extracted from radio
        double antenna_height_m = 10.0;  // Default antenna height - could be vehicle-specific
        
        float ss = this->calcPowerDistance(power, slantDist, frequency_mhz, alt1, antenna_height_m);
        if (ss <= 0.0) return signal; // in case signal strength got negative, that means we are out of range (too less tx-power)
        
        // NEW: Apply UHF antenna pattern gain
        try {
            // Calculate angles for antenna pattern lookup
            double theta_deg = this->degreeAboveHorizon(dist, alt2-alt1);  // Elevation angle
            double phi_deg = this->getDirection(lat1, lon1, lat2, lon2);   // Azimuth angle
            
            // Get frequency from radio (assuming 400 MHz for UHF)
            double frequency_mhz = 400.0; // Default UHF frequency
            
            // Determine UHF antenna name based on vehicle type
            std::string antenna_name = getUHFAntennaName("default", frequency_mhz);
            
            // Get UHF antenna gain from pattern interpolation
            double antenna_gain_db = getUHFGain(antenna_name, (int)alt1, frequency_mhz, theta_deg, phi_deg);
            
            // Apply antenna gain if pattern data is available
            if (antenna_gain_db > -999.0) {
                // Convert dB gain to linear multiplier
                double antenna_gain_linear = pow(10.0, antenna_gain_db / 10.0);
                ss *= antenna_gain_linear;
                
                // Ensure signal quality doesn't exceed 1.0
                if (ss > 1.0) ss = 1.0;
            }
        } catch (const std::exception& e) {
            // If antenna pattern lookup fails, continue with basic signal calculation
            // This ensures backward compatibility
        }
        
        // when distance is near the radio horizon, we smoothly cut off the signal, so it doesn't drop sharply to 0
        float usedRange = slantDist/radiodist;
        float usedRange_cutoffPct = 0.9; // at which percent of used radio horizon we start to cut off
        if (usedRange > usedRange_cutoffPct) {
            float loss    = (usedRange - usedRange_cutoffPct) * 10; //convert to percent range: 0.9=0%  0.95=0.5(50%)  1.0=1.0(100%)
            ss = ss * (1-loss); // apply loss to signal
        }
        
        // prepare return struct
        signal.quality       = ss;
        signal.direction     = this->getDirection(lat1, lon1, lat2, lon2);
        signal.verticalAngle = this->degreeAboveHorizon(dist, alt2-alt1);
        return signal;
    }
    
    
    // No channel names known so far. Are there any we must convert to real frequencies?
    std::string conv_chan2freq(std::string frq) {
        return frq;
    }
    
    std::string conv_freq2chan(std::string frq) {
        return frq;
    }
    
    // Frequency match is done with a band method, ie. a match is there if the bands overlap
    float getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
        if (r1.ptt)       return 0.0; // Half-duplex!
        if (!r1.operable) return 0.0; // stop if radio is inoperable

        // channel definition
        // TODO: Note, i completely made up those numbers. I have no idea of tuning UHF radios.
        float width_kHz = r1.channelWidth;
        if (width_kHz <= 0) width_kHz = 500.00;
        float channel_core  = 250.0;
        
        // see if we can it make more precise.
        // that is the case if we have numerical values (after ignoring prefixes).
        float filter = 0.0;
        try {
            fgcom_radiowave_freqConvRes frq1_p = FGCom_radiowaveModel::splitFreqString(r1.frequency);
            fgcom_radiowave_freqConvRes frq2_p = FGCom_radiowaveModel::splitFreqString(r2.frequency);
            if (frq1_p.isNumeric && frq2_p.isNumeric) {
                // numeric frequencies
                float frq1_f = std::stof(frq1_p.frequency);
                float frq2_f = std::stof(frq2_p.frequency);
                filter = this->getChannelAlignment(frq1_f, frq2_f, width_kHz, channel_core);
                return filter;
            } else {
                // not numeric: return default
                return filter;
            }
        } catch (const std::exception& e) {
            // fallback in case of errors: return default
            return filter;
        }
    }
    
    // everything else is borrowed from VHF model...
    
};
