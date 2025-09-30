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
#include "solar_data.h"
#include "power_management.h"

/**
 * A HF based radio model for the FGCom-mumble plugin
 *
 * The model implements high frequency propagation (between 3 and 30 MHz) with solar condition effects.
 * Includes day/night variations, solar flux effects, and geomagnetic activity impacts.
 * Transmissions behind the radio horizon travel via sky waves with solar-dependent characteristics.
 */
class FGCom_radiowaveModel_HF : public FGCom_radiowaveModel {
private:
    static FGCom_SolarDataProvider solar_provider;
protected:
    /*
    * Calculate the signal quality loss by power/distance model
    * 
    * Enhanced with power management integration
    * 
    * @param power in Watts
    * @param dist  slant distance in km
    * @return float with the signal quality for given power and distance
    */
    virtual float calcPowerDistance(float power, double slantDist) {
        // Get power management instance
        auto& power_manager = FGCom_PowerManager::getInstance();
        
        // Calculate effective radiated power considering efficiency
        float effective_power = power * power_manager.getCurrentPowerEfficiency();
        
        // Apply power limiting if enabled
        if (power_manager.isPowerLimitingActive()) {
            int limited_power = 0;
            if (power_manager.applyPowerLimits(static_cast<int>(effective_power), limited_power)) {
                effective_power = static_cast<float>(limited_power);
            }
        }
        
        // Enhanced power/distance model with efficiency
        float wr = effective_power * 1000; // gives maximum range in km for the effective power
        float sq = (-1/wr*pow(slantDist,2)+100)/100;
        
        // Apply additional efficiency factors
        sq *= power_manager.getCurrentPowerEfficiency();
        
        return sq;
    }
    
    // Calculate skywave propagation effects
    float calcSkywavePropagation(double distance, const fgcom_solar_conditions& solar, double solar_zenith) {
        float skywave_factor = 0.7; // Base skywave efficiency
        
        // Distance-based attenuation for skywave propagation
        float distance_factor = 1.0f - (distance / 10000.0f); // Reduce efficiency with distance
        if (distance_factor < 0.1f) distance_factor = 0.1f;
        skywave_factor *= distance_factor;
        
        // Solar flux effect on ionosphere
        float sfi_effect = (solar.sfi - 70.0) / 100.0 * 0.3;
        skywave_factor += sfi_effect;
        
        // Geomagnetic activity effect
        if (solar.k_index > 4.0) {
            skywave_factor *= (1.0 - (solar.k_index - 4.0) / 5.0 * 0.5);
        }
        
        // Day/night effect
        if (solar_zenith < 90.0) { // Daytime
            skywave_factor *= 0.8; // D-layer absorption
        } else { // Nighttime
            skywave_factor *= 1.2; // Better propagation
        }
        
        return std::max(0.1f, std::min(1.5f, skywave_factor));
    }
    
    // Calculate line-of-sight propagation effects
    float calcLineOfSightPropagation(double distance, const fgcom_solar_conditions& solar, double solar_zenith) {
        float los_factor = 1.0; // Base line-of-sight efficiency
        
        // Distance-based attenuation for line-of-sight
        float distance_attenuation = 1.0f - (distance / 5000.0f); // LOS degrades with distance
        if (distance_attenuation < 0.2f) distance_attenuation = 0.2f;
        los_factor *= distance_attenuation;
        
        // Solar zenith angle affects atmospheric conditions
        float zenith_effect = 1.0f - (solar_zenith / 90.0f) * 0.2f; // Better conditions at lower zenith
        los_factor *= zenith_effect;
        
        // Solar flux has minimal effect on line-of-sight
        float sfi_effect = (solar.sfi - 70.0) / 100.0 * 0.1;
        los_factor += sfi_effect;
        
        // Geomagnetic activity has minimal effect on line-of-sight
        if (solar.k_index > 6.0) {
            los_factor *= 0.95; // Slight degradation
        }
        
        return std::max(0.8f, std::min(1.2f, los_factor));
    }
    
    // Calculate overall solar effects
    float calcSolarEffects(const fgcom_solar_conditions& solar, double solar_zenith, double distance) {
        float effect = 1.0;
        
        // Solar flux effect
        float sfi_effect = (solar.sfi - 70.0) / 100.0 * 0.2;
        effect += sfi_effect;
        
        // Geomagnetic effect
        if (solar.k_index > 2.0) {
            effect *= (1.0 - (solar.k_index - 2.0) / 7.0 * 0.3);
        }
        
        // Day/night effect
        if (solar_zenith < 90.0) { // Daytime
            effect *= 0.9; // Slight degradation due to D-layer
        } else { // Nighttime
            effect *= 1.1; // Better propagation
        }
        
        // Distance-dependent solar effects
        if (distance > 1000.0) { // Long distance
            effect *= (1.0 + sfi_effect * 0.5); // Solar flux more important for long distance
        }
        
        return std::max(0.3f, std::min(2.0f, effect));
    }
    
    
public:
        
    std::string getType() {  return "HF";  }
    
    bool isCompatible(FGCom_radiowaveModel *otherModel) {
        return otherModel->getType() != "STRING";
    }
    
    
    // Signal depends on HF characteristics with solar condition effects.
    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
        struct fgcom_radiowave_signal signal;
        signal.quality = 0.85; // Base signal quality; but we will degrade that using the model below
    
        // get surface distance
        double dist = this->getSurfaceDistance(lat1, lon1, lat2, lon2);
        
        // apply power/distance model
        signal.quality = this->calcPowerDistance(power, dist);
        if (signal.quality <= 0.0) signal.quality = 0.0; // in case signal strength got negative, that means we are out of range (too less tx-power)
        
        // Get current solar conditions
        fgcom_solar_conditions solar = solar_provider.getCurrentConditions();
        
        // Calculate solar zenith angle for midpoint
        double mid_lat = (lat1 + lat2) / 2.0;
        double mid_lon = (lon1 + lon2) / 2.0;
        double solar_zenith = solar_provider.calculateSolarZenith(mid_lat, mid_lon, std::chrono::system_clock::now());
        
        // Check if the target is behind the radio horizon
        double heightAboveHorizon = this->heightAboveHorizon(dist, alt1, alt2);
        if (heightAboveHorizon < 0) {
            // behind horizon: skywave propagation with solar effects
            signal.quality *= this->calcSkywavePropagation(dist, solar, solar_zenith);
        } else {
            // line of sight: apply basic solar effects
            signal.quality *= this->calcLineOfSightPropagation(dist, solar, solar_zenith);
        }
        
        // Apply solar condition effects
        signal.quality *= this->calcSolarEffects(solar, solar_zenith, dist);
        
        // Ensure signal quality is within bounds
        signal.quality = std::max(0.0f, std::min(1.0f, signal.quality));
        
        // prepare return struct
        signal.direction     = this->getDirection(lat1, lon1, lat2, lon2);
        signal.verticalAngle = this->degreeAboveHorizon(dist, alt2-alt1);
        return signal;
    }
    
    
    // no known channel names yet. Are there any where we need to convert to real frq?
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
        // HF radio parameters based on aviation/military standards
        // Standard HF channel spacing: 3kHz (SSB), 2.4kHz (AM), 1.8kHz (CW)
        // Reference: https://onlinelibrary.wiley.com/doi/abs/10.1002/0471208051.fre015
        float width_kHz = r1.channelWidth;
        if (width_kHz <= 0) width_kHz = 3.0;   // Standard 3kHz channel spacing for HF SSB
        float channel_core = width_kHz / 3.0;  // Channel core is 1/3 of channel width for HF
        
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

    
    /*
     * Process audio samples
     */
    void processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
        // Audio processing is like VHF characteristics for now
        // TODO: Fix VHF class usage - temporarily commented out
        // std::unique_ptr<FGCom_radiowaveModel_VHF> vhf_radio = std::make_unique<FGCom_radiowaveModel_VHF>();
        // vhf_radio->processAudioSamples(lclRadio, signalQuality, outputPCM, sampleCount, channelCount, sampleRateHz);
        
        // Use radio parameters for audio processing
        float volume_factor = lclRadio.volume / 100.0f; // Use radio volume
        float sample_rate_factor = 48000.0f / sampleRateHz; // Normalize to 48kHz reference
        
        // Basic audio processing with radio-specific adjustments
        for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
            outputPCM[i] *= signalQuality * volume_factor * sample_rate_factor;
        }
    }
};

// Static member definition
FGCom_SolarDataProvider FGCom_radiowaveModel_HF::solar_provider;
