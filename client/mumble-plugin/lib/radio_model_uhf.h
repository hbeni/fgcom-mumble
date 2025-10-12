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

#ifndef RADIO_MODEL_UHF_H
#define RADIO_MODEL_UHF_H

#include "radio_model.h"
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
    void initializeUHFPatterns();
    
    // Load UHF antenna patterns for various vehicles
    void loadUHFAntennaPatterns();
    void loadMilitaryUHFPatterns();
    void loadCivilianUHFPatterns();
    void loadAircraftUHFPatterns();
    void loadGroundVehicleUHFPatterns();
    void loadMaritimeUHFPatterns();
    
    // Get UHF antenna gain from pattern interpolation
    double getUHFGain(const std::string& antenna_name, int altitude_m, 
                     double frequency_mhz, double theta_deg, double phi_deg,
                     int roll_deg = 0, int pitch_deg = 0);
    
    // Determine UHF antenna name based on vehicle type and frequency
    std::string getUHFAntennaName(const std::string& vehicle_type, double frequency_mhz);
    
public:
    FGCom_radiowaveModel_UHF();
    virtual ~FGCom_radiowaveModel_UHF();
    
    // Override base class methods
    virtual void processAudioSamples(fgcom_radio lclRadio, float signalQuality, 
                                   float* outputPCM, uint32_t sampleCount, 
                                   uint16_t channelCount, uint32_t sampleRateHz) override;
    
    virtual fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1,
                          double lat2, double lon2, float alt2, float power) override;
    
    // UHF-specific power distance calculation
    float calcPowerDistance(float power_watts, double distance_km, 
                          double frequency_mhz, double altitude_m, double antenna_height_m);
    
    // 4-parameter version for implementation compatibility
    float calcPowerDistance(float power_watts, double distance_km, 
                          double altitude_m, double frequency_mhz);
    
    // Legacy method for backward compatibility
    float calcPowerDistance(float power_watts, double distance_km);
    
    // Required virtual methods from base class
    virtual std::string getType() override;
    virtual std::string conv_chan2freq(std::string frq) override;
    virtual std::string conv_freq2chan(std::string frq) override;
    virtual float getFrqMatch(fgcom_radio r1, fgcom_radio r2) override;
    
    // UHF-specific methods
    float getAntennaGain(const std::string& antenna_name, int frequency_mhz, 
                        double elevation_deg, double azimuth_deg, double altitude_m, 
                        int vehicle_type, int antenna_type);
    
    // Get available UHF patterns
    std::vector<std::string> getAvailableUHFPatterns() const;
    
    // Check if pattern is available
    bool hasUHFPattern(const std::string& pattern_name) const;
    
    // UHF-specific audio processing
    void processAudioSamples_UHF(int highpass_cutoff, int lowpass_cutoff, 
                                float minimumNoiseVolume, float maximumNoiseVolume, 
                                fgcom_radio lclRadio, float signalQuality, 
                                float *outputPCM, uint32_t sampleCount, 
                                uint16_t channelCount, uint32_t sampleRateHz);
};

#endif // RADIO_MODEL_UHF_H
