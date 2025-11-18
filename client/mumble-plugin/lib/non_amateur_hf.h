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

#ifndef FGCOM_NON_AMATEUR_HF_H
#define FGCOM_NON_AMATEUR_HF_H

#include <string>
#include <vector>
#include <map>
#include "radio_model.h"

// Aviation HF band structure
struct fgcom_aviation_hf_band {
    std::string name;           // Band name (e.g., "2.85MHz", "3.4MHz", "8.815MHz")
    float start_freq;           // Start frequency in kHz
    float end_freq;             // End frequency in kHz
    std::string modulation;     // "USB" for aviation HF
    float filter_bandwidth;     // 3kHz for USB
    std::string service_type;   // "AERONAUTICAL"
    std::string notes;          // Additional information
};

// MWARA frequency structure
struct fgcom_mwara_frequency {
    std::string region;         // Region (NAT, CAR, SAT, SAM, EUR, etc.)
    float frequency;            // Frequency in kHz
    std::string service_type;   // "MWARA", "VOLMET", "RADRA"
    std::string notes;          // Additional information
};

// Maritime HF channel structure
struct fgcom_maritime_channel {
    int channel_number;         // ITU channel number
    std::string band;           // Band (4MHz, 6MHz, 8MHz, etc.)
    float coast_freq;           // Coast station frequency in kHz
    float ship_freq;            // Ship station frequency in kHz
    std::string service_type;   // "MARITIME"
    std::string notes;          // Special notes (USCG Calling, etc.)
    bool is_simplex;            // True for simplex channels
};

// Aviation HF radio structure
struct fgcom_aviation_hf_radio : public fgcom_radio {
    std::string aircraft_type;  // "COMMERCIAL", "MILITARY", "GENERAL_AVIATION"
    float altitude_ft;          // Aircraft altitude in feet
    std::string callsign;       // Aircraft callsign
    std::string registration;   // Aircraft registration
    bool is_usb_modulation;     // USB modulation flag (HF aviation uses USB)
    float usb_bandwidth;        // USB filter bandwidth (3kHz)
    std::string mwara_region;   // MWARA region (NAT, CAR, SAT, etc.)
    
    fgcom_aviation_hf_radio() : fgcom_radio() {
        aircraft_type = "COMMERCIAL";
        altitude_ft = 35000.0;  // Default cruise altitude
        callsign = "";
        registration = "";
        is_usb_modulation = true;
        usb_bandwidth = 3.0;    // 3kHz USB bandwidth
        mwara_region = "NAT";   // Default to North Atlantic
    };
};

// Maritime HF radio structure
struct fgcom_maritime_hf_radio : public fgcom_radio {
    std::string vessel_type;    // "COMMERCIAL", "FISHING", "PLEASURE", "MILITARY"
    std::string callsign;       // Vessel callsign
    std::string mmsi;           // Maritime Mobile Service Identity
    std::string flag_state;     // Flag state
    bool is_duplex;             // Duplex operation flag
    int itu_channel;            // ITU channel number
    
    fgcom_maritime_hf_radio() : fgcom_radio() {
        vessel_type = "COMMERCIAL";
        callsign = "";
        mmsi = "";
        flag_state = "";
        is_duplex = true;
        itu_channel = 0;
    };
};

// Non-amateur HF utility functions
class FGCom_NonAmateurHF {
private:
    static std::vector<fgcom_aviation_hf_band> aviation_bands;
    static std::vector<fgcom_maritime_channel> maritime_channels;
    static std::vector<fgcom_mwara_frequency> mwara_frequencies;
    static bool initialized;
    
public:
    // Initialize non-amateur HF data
    static bool initialize();
    
    // Aviation HF functions
    static std::vector<fgcom_aviation_hf_band> getAviationBands();
    static fgcom_aviation_hf_band getAviationBand(float frequency_khz);
    static bool isAviationFrequency(float frequency_khz);
    static float calculateAviationPropagation(float frequency_khz, double distance_km, float altitude1_ft, float altitude2_ft);
    static float calculateWhipAntennaEfficiency(float frequency_khz, float altitude_ft);
    static float calculateHighAltitudeEffects(float altitude_ft, double distance_km);
    
    // MWARA functions
    static std::vector<fgcom_mwara_frequency> getMWARAFrequencies();
    static std::vector<fgcom_mwara_frequency> getMWARAFrequenciesByRegion(const std::string& region);
    static bool isMWARAFrequency(float frequency_khz);
    static fgcom_mwara_frequency getMWARAFrequency(float frequency_khz);
    static std::vector<std::string> getMWARARegions();
    
    // Maritime HF functions
    static std::vector<fgcom_maritime_channel> getMaritimeChannels();
    static fgcom_maritime_channel getMaritimeChannel(int channel_number);
    static fgcom_maritime_channel getMaritimeChannelByFrequency(float frequency_khz);
    static bool isMaritimeFrequency(float frequency_khz);
    static float calculateMaritimePropagation(float frequency_khz, double distance_km, float altitude1_ft, float altitude2_ft);
    static float calculateSeaPathEffects(double distance_km, float altitude_ft);
    
    // Channel conversion functions
    static std::string aviationFreqToChannel(float frequency_khz);
    static std::string maritimeFreqToChannel(float frequency_khz);
    static float aviationChannelToFreq(const std::string& channel);
    static float maritimeChannelToFreq(const std::string& channel);
    
    // Modulation and bandwidth functions
    static float getUSBBandwidth(float frequency_khz);
    static float getSSBBandwidth(float frequency_khz);
    static std::string getModulationType(float frequency_khz);
    
private:
    // Internal initialization methods
    static void setupAviationBands();
    static void setupMaritimeChannels();
    static void setupMWARAFrequencies();
    static void loadUSCGMaritimeChannels();
};

// Aviation HF radio model
class FGCom_radiowaveModel_AviationHF : public FGCom_radiowaveModel {
private:
    float aircraft_altitude_ft;
    std::string aircraft_type;
    
public:
    FGCom_radiowaveModel_AviationHF(float altitude_ft = 35000.0, const std::string& type = "COMMERCIAL");
    
    std::string getType() override;
    bool isCompatible(FGCom_radiowaveModel *otherModel) override;
    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) override;
    std::string conv_chan2freq(std::string frq) override;
    std::string conv_freq2chan(std::string frq) override;
    float getFrqMatch(fgcom_radio r1, fgcom_radio r2) override;
    void processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) override;
    
    // Aviation-specific methods
    float calculateWhipAntennaEfficiency(float frequency_khz);
    float calculateHighAltitudePropagation(double distance_km, float frequency_khz);
    float calculateUSBModulationEffects(float frequency_khz);
};

// Maritime HF radio model
class FGCom_radiowaveModel_MaritimeHF : public FGCom_radiowaveModel {
private:
    std::string vessel_type;
    bool is_duplex_operation;
    
public:
    FGCom_radiowaveModel_MaritimeHF(const std::string& type = "COMMERCIAL", bool duplex = true);
    
    std::string getType() override;
    bool isCompatible(FGCom_radiowaveModel *otherModel) override;
    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) override;
    std::string conv_chan2freq(std::string frq) override;
    std::string conv_freq2chan(std::string frq) override;
    float getFrqMatch(fgcom_radio r1, fgcom_radio r2) override;
    void processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) override;
    
    // Maritime-specific methods
    float calculateSeaPathPropagation(double distance_km, float frequency_khz);
    float calculateMaritimeChannelEffects(int channel_number);
    float calculateDuplexOperationEffects(bool is_duplex);
};

#endif // FGCOM_NON_AMATEUR_HF_H
