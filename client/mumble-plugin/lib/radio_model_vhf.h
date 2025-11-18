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

#ifndef RADIO_MODEL_VHF_H
#define RADIO_MODEL_VHF_H

#include "radio_model.h"
#include "pattern_interpolation.h"
#include "antenna_ground_system.h"
#include "antenna_pattern_mapping.h"
#include "propagation_physics.h"
#include "atmospheric_ducting.h"
#include "enhanced_multipath.h"

/**
 * A VHF based radio model for the FGCom-mumble plugin
 *
 * The model implements basic line-of-sight characteristics for VHF spectrum (30 to 300 MHz).
 */
class FGCom_radiowaveModel_VHF : public FGCom_radiowaveModel {
private:
    // Antenna pattern interpolation system
    std::unique_ptr<FGCom_PatternInterpolation> pattern_interpolation;
    std::unique_ptr<FGCom_AntennaGroundSystem> antenna_system;
    bool patterns_initialized;
    
    // Atmospheric ducting system
    std::unique_ptr<FGCom_AtmosphericDucting> atmospheric_ducting;
    bool ducting_initialized;
    
    // Enhanced multipath system
    std::unique_ptr<FGCom_EnhancedMultipath> enhanced_multipath;
    bool multipath_initialized;
    
    // Initialize antenna patterns for VHF frequencies
    void initializePatterns();
    
    // Initialize atmospheric ducting system
    void initializeDucting();
    
    // Initialize enhanced multipath system
    void initializeMultipath();
    
    // Load VHF antenna patterns for various vehicles
    void loadVHFAntennaPatterns();
    void loadAircraftVHFPatterns();
    void loadAircraft3DAttitudePatterns();
    void loadGroundVehicleVHFPatterns();
    void loadMaritimeVHFPatterns();

public:
    FGCom_radiowaveModel_VHF();
    virtual ~FGCom_radiowaveModel_VHF();
    
    // Override base class methods
    virtual void processAudioSamples(fgcom_radio lclRadio, float signalQuality, 
                                   float* outputPCM, uint32_t sampleCount, 
                                   uint16_t channelCount, uint32_t sampleRateHz) override;
    
    virtual fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1,
                          double lat2, double lon2, float alt2, float power) override;
    
    // VHF-specific power distance calculation
    float calcPowerDistance(float power_watts, double distance_km, 
                          double altitude_m, double frequency_mhz);
    
    // Required virtual methods from base class
    virtual std::string getType() override;
    virtual std::string conv_chan2freq(std::string frq) override;
    virtual std::string conv_freq2chan(std::string frq) override;
    virtual float getFrqMatch(fgcom_radio r1, fgcom_radio r2) override;
    
    // VHF-specific methods
    float getAntennaGain(const std::string& antenna_name, int frequency_mhz, 
                        double elevation_deg, double azimuth_deg, double altitude_m, 
                        int vehicle_type, int antenna_type);
    
    // Get available VHF patterns
    std::vector<std::string> getAvailableVHFPatterns() const;
    
    // Check if pattern is available
    bool hasVHFPattern(const std::string& pattern_name) const;
    
    // VHF-specific audio processing
    void processAudioSamples_VHF(int highpass_cutoff, int lowpass_cutoff, 
                                float minimumNoiseVolume, float maximumNoiseVolume, 
                                fgcom_radio lclRadio, float signalQuality, 
                                float *outputPCM, uint32_t sampleCount, 
                                uint16_t channelCount, uint32_t sampleRateHz);
};

#endif // RADIO_MODEL_VHF_H
