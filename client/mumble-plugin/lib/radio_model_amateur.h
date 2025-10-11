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

#ifndef RADIO_MODEL_AMATEUR_H
#define RADIO_MODEL_AMATEUR_H

#include <iostream> 
#include <cmath>
#include <regex>
#include "radio_model.h"
#include "amateur_radio.h"
#include "audio.h"
#include "solar_data.h"

/**
 * An amateur radio model for the FGCom-mumble plugin
 *
 * This model implements amateur radio specific propagation characteristics
 * based on band-specific properties and ITU regional regulations.
 */
class FGCom_radiowaveModel_Amateur : public FGCom_radiowaveModel {
private:
    int itu_region;  // ITU region for this instance
    static FGCom_SolarDataProvider& getSolarProvider() {
        static FGCom_SolarDataProvider provider;
        return provider;
    }
    
public:
    FGCom_radiowaveModel_Amateur(int region = 1) : itu_region(region) {
        // Initialize amateur radio data
        FGCom_AmateurRadio::initialize();
    }
    
    std::string getType() { return "AMATEUR"; }
    
    bool isCompatible(FGCom_radiowaveModel *otherModel) {
        return otherModel->getType() == "AMATEUR" || otherModel->getType() == "HF";
    }
    
    // Amateur radio signal calculation with band-specific characteristics
    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
        struct fgcom_radiowave_signal signal;
        signal.quality = 0.0;
        
        // Get surface distance
        double dist = this->getSurfaceDistance(lat1, lon1, lat2, lon2);
        
        // For amateur radio, we need to determine the band from frequency
        // This is a simplified approach - in practice, we'd get this from the radio state
        float center_freq = 7100.0; // Default to 40m band
        std::string band = FGCom_AmateurRadio::frequencyToBand(center_freq);
        
        if (band.empty()) {
            return signal; // Not an amateur frequency
        }
        
        // Get band characteristics
        fgcom_band_characteristics characteristics = FGCom_AmateurRadio::getBandCharacteristics(band);
        
        // Get current solar conditions
        fgcom_solar_conditions solar = getSolarProvider().getCurrentConditions();
        
        // Calculate solar zenith angle for midpoint
        double mid_lat = (lat1 + lat2) / 2.0;
        double mid_lon = (lon1 + lon2) / 2.0;
        // double solar_zenith = solar_provider.calculateSolarZenith(mid_lat, mid_lon, std::chrono::system_clock::now());
        
        // Calculate signal quality based on band-specific propagation
        // Simplified implementation for now
        if (characteristics.propagation == "Ground wave") {
            // Ground wave propagation (160m, 80m)
            signal.quality = 0.8f * (power / 100.0f) * (1.0f - dist / 1000.0f);
        } else if (characteristics.propagation == "Sky wave") {
            // Sky wave propagation (40m, 20m, etc.)
            signal.quality = 0.7f * (power / 100.0f) * (1.0f - dist / 5000.0f);
        } else if (characteristics.propagation == "Line of sight") {
            // Line of sight propagation (6m, 2m, etc.)
            signal.quality = 0.9f * (power / 100.0f) * (1.0f - dist / 500.0f);
        } else {
            // Mixed propagation (10m)
            signal.quality = 0.75f * (power / 100.0f) * (1.0f - dist / 2000.0f);
        }
        
        // Apply solar effects for amateur radio bands
        signal.quality *= (solar.sfi / 100.0f); // Solar flux effect
        signal.quality *= (1.0f - solar.k_index / 20.0f); // Geomagnetic activity effect
        
        // Apply day/night factor
        signal.quality *= characteristics.day_night_factor;
        
        // Apply distance-based attenuation
        if (dist > characteristics.max_range_km) {
            signal.quality *= (characteristics.max_range_km / dist);
        }
        
        // Ensure signal quality is within bounds
        signal.quality = std::max(0.0f, std::min(1.0f, signal.quality));
        
        // Calculate direction and vertical angle
        signal.direction = this->getDirection(lat1, lon1, lat2, lon2);
        signal.verticalAngle = this->degreeAboveHorizon(dist, alt2-alt1);
        
        return signal;
    }

    std::string conv_chan2freq(std::string frq) {
        // Amateur radio frequencies are already in proper format
        return frq;
    }

    std::string conv_freq2chan(std::string frq) {
        // Amateur radio frequencies are already in proper format
        return frq;
    }

    float getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
        if (!r1.operable) return 0.0; // stop if radio is inoperable

        // Amateur radios can communicate if frequencies are close enough
        // Allow some tolerance for amateur radio propagation
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
        // Basic audio processing for amateur radio
        // Use radio volume and sample rate for processing
        float radio_volume = lclRadio.volume / 100.0f;
        float sample_rate_normalization = 48000.0f / sampleRateHz;
        
        // Apply signal quality as volume scaling with radio parameters
        for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
            outputPCM[i] *= signalQuality * radio_volume * sample_rate_normalization;
        }
    }
};

#endif // RADIO_MODEL_AMATEUR_H
