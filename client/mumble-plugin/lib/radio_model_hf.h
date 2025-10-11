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

#ifndef RADIO_MODEL_HF_H
#define RADIO_MODEL_HF_H

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
    static FGCom_SolarDataProvider& getSolarProvider() {
        static FGCom_SolarDataProvider provider;
        return provider;
    }
    
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
        float kp_effect = (solar.k_index - 2.0) / 10.0 * 0.2;
        skywave_factor -= kp_effect;
        
        // Day/night variation
        float day_night_factor = (solar_zenith > 90.0) ? 0.8f : 1.2f; // Better at night
        skywave_factor *= day_night_factor;
        
        // Clamp to reasonable range
        if (skywave_factor < 0.1f) skywave_factor = 0.1f;
        if (skywave_factor > 1.0f) skywave_factor = 1.0f;
        
        return skywave_factor;
    }
    
public:
    std::string getType() {  return "HF";  }
    
    bool isCompatible(FGCom_radiowaveModel *otherModel) {
        return otherModel->getType() != "STRING";
    }

    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
        struct fgcom_radiowave_signal signal;
        signal.quality = 0.85; // Base signal quality; but we will degrade that using the model below
    
        // get surface distance
        double dist = this->getSurfaceDistance(lat1, lon1, lat2, lon2);
        
        // Get solar conditions
        fgcom_solar_conditions solar = getSolarProvider().getCurrentConditions();
        
        // Calculate solar zenith angle for day/night effects
        double solar_zenith = getSolarProvider().calculateSolarZenith(lat1, lon1, std::chrono::system_clock::now());
        
        // Check if we need skywave propagation (behind radio horizon)
        double radio_horizon = this->getDistToHorizon(alt1) + this->getDistToHorizon(alt2);
        bool needs_skywave = dist > radio_horizon;
        
        if (needs_skywave) {
            // Skywave propagation
            float skywave_factor = calcSkywavePropagation(dist, solar, solar_zenith);
            signal.quality *= skywave_factor;
        } else {
            // Line-of-sight propagation
            signal.quality *= this->calcPowerDistance(power, dist);
        }
        
        // Apply solar conditions
        signal.quality *= (solar.sfi / 100.0f); // Solar flux effect
        signal.quality *= (1.0f - solar.k_index / 20.0f); // Geomagnetic activity effect
        
        // Clamp quality
        if (signal.quality < 0.0f) signal.quality = 0.0f;
        if (signal.quality > 1.0f) signal.quality = 1.0f;
        
        signal.direction = this->getDirection(lat1, lon1, lat2, lon2);
        signal.verticalAngle = this->degreeAboveHorizon(dist, alt2-alt1);
        
        return signal;
    }

    std::string conv_chan2freq(std::string frq) {
        return frq; // HF frequencies are already in proper format
    }

    std::string conv_freq2chan(std::string frq) {
        return frq; // HF frequencies are already in proper format
    }

    float getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
        if (!r1.operable) return 0.0; // stop if radio is inoperable

        // HF radios can communicate if frequencies are close enough
        // Allow some tolerance for HF propagation
        float freq1 = std::stof(r1.frequency);
        float freq2 = std::stof(r2.frequency);
        float tolerance = 0.1f; // 100kHz tolerance
        
        if (std::abs(freq1 - freq2) <= tolerance) {
            return 1.0f;
        }
        
        return 0.0f;
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

#endif // RADIO_MODEL_HF_H
