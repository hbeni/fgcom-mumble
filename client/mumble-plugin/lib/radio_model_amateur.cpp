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
    static FGCom_SolarDataProvider solar_provider;
    
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
        fgcom_solar_conditions solar = solar_provider.getCurrentConditions();
        
        // Calculate solar zenith angle for midpoint
        double mid_lat = (lat1 + lat2) / 2.0;
        double mid_lon = (lon1 + lon2) / 2.0;
        double solar_zenith = solar_provider.calculateSolarZenith(mid_lat, mid_lon, std::chrono::system_clock::now());
        
        // Calculate signal quality based on band-specific propagation
        if (characteristics.propagation == "Ground wave") {
            // Ground wave propagation (160m, 80m)
            signal.quality = this->calcGroundWaveSignal(power, dist, characteristics);
        } else if (characteristics.propagation == "Sky wave") {
            // Sky wave propagation (40m, 20m, etc.)
            signal.quality = this->calcSkyWaveSignal(power, dist, characteristics, alt1, alt2);
        } else if (characteristics.propagation == "Line of sight") {
            // Line of sight propagation (6m, 2m, etc.)
            signal.quality = this->calcLineOfSightSignal(power, dist, characteristics, alt1, alt2);
        } else {
            // Mixed propagation (10m)
            signal.quality = this->calcMixedPropagationSignal(power, dist, characteristics, alt1, alt2);
        }
        
        // Apply solar effects for amateur radio bands
        signal.quality *= this->calcAmateurSolarEffects(solar, solar_zenith, dist, band);
        
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
    
    // Grid-based signal calculation for amateur radio contacts
    fgcom_radiowave_signal getSignalFromGrid(const std::string& grid1, float alt1, const std::string& grid2, float alt2, float power, const std::string& band) {
        struct fgcom_radiowave_signal signal;
        signal.quality = 0.0;
        
        // Validate grid locators
        if (!FGCom_AmateurRadio::validateGridLocator(grid1) || !FGCom_AmateurRadio::validateGridLocator(grid2)) {
            return signal; // Invalid grid locators
        }
        
        // Convert grid locators to lat/lon
        double lat1, lon1, lat2, lon2;
        FGCom_AmateurRadio::gridToLatLon(grid1, lat1, lon1);
        FGCom_AmateurRadio::gridToLatLon(grid2, lat2, lon2);
        
        // Calculate distance using grid-based calculation
        double grid_dist = FGCom_AmateurRadio::gridDistance(grid1, grid2);
        
        // Get band characteristics
        fgcom_band_characteristics characteristics = FGCom_AmateurRadio::getBandCharacteristics(band);
        
        // Calculate signal quality based on band-specific propagation
        if (characteristics.propagation == "Ground wave") {
            signal.quality = this->calcGroundWaveSignal(power, grid_dist, characteristics);
        } else if (characteristics.propagation == "Sky wave") {
            signal.quality = this->calcSkyWaveSignal(power, grid_dist, characteristics, alt1, alt2);
        } else if (characteristics.propagation == "Line of sight") {
            signal.quality = this->calcLineOfSightSignal(power, grid_dist, characteristics, alt1, alt2);
        } else {
            signal.quality = this->calcMixedPropagationSignal(power, grid_dist, characteristics, alt1, alt2);
        }
        
        // Apply day/night factor
        signal.quality *= characteristics.day_night_factor;
        
        // Apply distance-based attenuation
        if (grid_dist > characteristics.max_range_km) {
            signal.quality *= (characteristics.max_range_km / grid_dist);
        }
        
        // Ensure signal quality is within bounds
        signal.quality = std::max(0.0f, std::min(1.0f, signal.quality));
        
        // Calculate direction and vertical angle using grid-based bearing
        signal.direction = FGCom_AmateurRadio::gridBearing(grid1, grid2);
        signal.verticalAngle = this->degreeAboveHorizon(grid_dist, alt2-alt1);
        
        return signal;
    }
    
    // Ground wave propagation calculation
    float calcGroundWaveSignal(float power, double dist, const fgcom_band_characteristics& characteristics) {
        // Ground wave follows inverse square law with some absorption
        float base_signal = (power * 10.0) / (dist * dist + 1.0);
        return std::min(1.0f, base_signal / 100.0f);
    }
    
    // Sky wave propagation calculation
    float calcSkyWaveSignal(float power, double dist, const fgcom_band_characteristics& characteristics, float alt1, float alt2) {
        // Sky wave can travel long distances via ionospheric reflection
        float base_signal = (power * 5.0) / (dist + 100.0);
        
        // Apply altitude factor (higher altitude = better signal)
        float altitude_factor = 1.0 + ((alt1 + alt2) / 2000.0) * 0.5;
        
        return std::min(1.0f, base_signal * altitude_factor / 50.0f);
    }
    
    // Line of sight propagation calculation
    float calcLineOfSightSignal(float power, double dist, const fgcom_band_characteristics& characteristics, float alt1, float alt2) {
        // Check if line of sight is possible
        double heightAboveHorizon = this->heightAboveHorizon(dist, alt1, alt2);
        if (heightAboveHorizon < 0) {
            return 0.0; // No line of sight
        }
        
        // Line of sight follows inverse square law
        float base_signal = (power * 20.0) / (dist * dist + 1.0);
        return std::min(1.0f, base_signal / 200.0f);
    }
    
    // Mixed propagation calculation (ground wave + sky wave)
    float calcMixedPropagationSignal(float power, double dist, const fgcom_band_characteristics& characteristics, float alt1, float alt2) {
        // Combine ground wave and sky wave components
        float ground_wave = calcGroundWaveSignal(power, dist, characteristics);
        float sky_wave = calcSkyWaveSignal(power, dist, characteristics, alt1, alt2);
        
        // Use the stronger signal
        return std::max(ground_wave, sky_wave);
    }
    
    // Calculate solar effects specific to amateur radio bands
    float calcAmateurSolarEffects(const fgcom_solar_conditions& solar, double solar_zenith, double distance, const std::string& band) {
        float effect = 1.0;
        
        // Solar flux effect (more important for HF bands)
        if (band == "160m" || band == "80m" || band == "40m" || band == "20m" || band == "15m" || band == "10m") {
            float sfi_effect = (solar.sfi - 70.0) / 100.0 * 0.4; // Stronger effect for HF
            effect += sfi_effect;
        } else {
            float sfi_effect = (solar.sfi - 70.0) / 100.0 * 0.1; // Minimal effect for VHF/UHF
            effect += sfi_effect;
        }
        
        // Geomagnetic effect (affects all bands but more for HF)
        if (solar.k_index > 2.0) {
            float geomag_factor = (solar.k_index - 2.0) / 7.0;
            if (band == "160m" || band == "80m" || band == "40m") {
                effect *= (1.0 - geomag_factor * 0.6); // Strong effect on lower HF
            } else if (band == "20m" || band == "15m" || band == "10m") {
                effect *= (1.0 - geomag_factor * 0.4); // Moderate effect on upper HF
            } else {
                effect *= (1.0 - geomag_factor * 0.2); // Light effect on VHF/UHF
            }
        }
        
        // Day/night effect (band-specific)
        if (solar_zenith < 90.0) { // Daytime
            if (band == "160m" || band == "80m") {
                effect *= 0.6; // Heavy D-layer absorption
            } else if (band == "40m") {
                effect *= 0.7; // Moderate absorption
            } else if (band == "20m" || band == "15m") {
                effect *= 0.8; // Light absorption
            } else if (band == "10m") {
                effect *= 0.9; // Minimal absorption
            } else {
                effect *= 1.0; // No absorption for VHF/UHF
            }
        } else { // Nighttime
            if (band == "160m" || band == "80m" || band == "40m") {
                effect *= 1.3; // Better propagation at night
            } else if (band == "20m" || band == "15m") {
                effect *= 1.1; // Slightly better
            } else {
                effect *= 1.0; // No change for higher bands
            }
        }
        
        // Distance-dependent effects
        if (distance > 500.0) { // Long distance
            if (band == "160m" || band == "80m" || band == "40m") {
                effect *= (1.0 + (solar.sfi - 70.0) / 100.0 * 0.3); // Solar flux more important for long distance HF
            }
        }
        
        return std::max(0.2f, std::min(2.0f, effect));
    }
    
    // Convert channel to frequency (amateur radio specific)
    std::string conv_chan2freq(std::string frq) {
        // For amateur radio, frequencies are usually given directly
        // But we might need to handle band-specific conversions
        return frq;
    }
    
    std::string conv_freq2chan(std::string frq) {
        // Convert frequency to channel name if applicable
        return frq;
    }
    
    // Frequency matching for amateur radio
    float getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
        // For amateur radio, we need to check if frequencies are in the same band segment
        float freq1 = std::stof(r1.frequency);
        float freq2 = std::stof(r2.frequency);
        
        // Get band segments for both frequencies
        fgcom_band_segment seg1 = FGCom_AmateurRadio::getBandSegment(freq1, itu_region);
        fgcom_band_segment seg2 = FGCom_AmateurRadio::getBandSegment(freq2, itu_region);
        
        // If both are in the same band and mode, they match
        if (seg1.band == seg2.band && seg1.mode == seg2.mode) {
            return 1.0; // Perfect match
        }
        
        // If in the same band but different modes, partial match
        if (seg1.band == seg2.band) {
            return 0.5; // Partial match
        }
        
        return 0.0; // No match
    }
    
    // Validate amateur radio frequency
    bool validateFrequency(const std::string& frequency, const std::string& mode) {
        return FGCom_AmateurRadio::validateAmateurFrequency(frequency, mode, itu_region);
    }
    
    // Get available bands for this region
    std::vector<std::string> getAvailableBands() {
        return FGCom_AmateurRadio::getAvailableBands(itu_region);
    }
    
    // Get available modes for a band
    std::vector<std::string> getAvailableModes(const std::string& band) {
        return FGCom_AmateurRadio::getAvailableModes(band, itu_region);
    }
};

// Static member definition
FGCom_SolarDataProvider FGCom_radiowaveModel_Amateur::solar_provider;

