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

#ifndef FGCOM_AMATEUR_RADIO_H
#define FGCOM_AMATEUR_RADIO_H

#include <string>
#include <vector>
#include <map>
#include "radio_model.h"

// Band segment structure for amateur radio frequency allocations
struct fgcom_band_segment {
    std::string band;           // "160m", "80m", "40m", etc.
    std::string mode;           // "CW", "SSB", "AM", "DSB", "ISB", "VSB"
    float start_freq;           // Start frequency in kHz
    float end_freq;             // End frequency in kHz
    int itu_region;             // ITU Region (1, 2, 3)
    std::string notes;          // Additional notes/restrictions
    
    fgcom_band_segment() {
        band = "";
        mode = "";
        start_freq = 0.0;
        end_freq = 0.0;
        itu_region = 1;
        notes = "";
    }
};

// Band characteristics for amateur radio propagation
struct fgcom_band_characteristics {
    std::string band;           // Band name
    float center_freq;          // Center frequency in kHz
    float wavelength;           // Wavelength in meters
    std::string propagation;    // "Ground wave", "Sky wave", "Line of sight"
    float max_range_km;         // Typical maximum range in km
    float day_night_factor;     // Day/night propagation factor
    bool dx_capable;            // DX (long distance) capable
    
    fgcom_band_characteristics() {
        band = "";
        center_freq = 0.0;
        wavelength = 0.0;
        propagation = "";
        max_range_km = 0.0;
        day_night_factor = 1.0;
        dx_capable = false;
    }
};

// ITU Region detection based on coordinates
struct fgcom_itu_region {
    int region;                 // 1, 2, or 3
    std::string name;           // Region name
    float min_lat, max_lat;     // Latitude bounds
    float min_lon, max_lon;     // Longitude bounds
    
    fgcom_itu_region() {
        region = 1;
        name = "";
        min_lat = max_lat = min_lon = max_lon = 0.0;
    }
};

// Maidenhead grid locator structure
struct fgcom_grid_locator {
    std::string grid;           // Full grid locator (e.g., "FN31pr")
    double lat, lon;           // Calculated latitude/longitude
    bool valid;                // Whether the grid locator is valid
    
    fgcom_grid_locator() {
        grid = "";
        lat = lon = 0.0;
        valid = false;
    }
};

// Frequency validation result
struct fgcom_frequency_validation {
    bool valid;                // Whether frequency is valid
    std::string band;          // Band name if valid
    std::string mode;          // Mode if valid
    std::string error_message; // Error message if invalid
    float channel_spacing;     // Required channel spacing in Hz
    
    fgcom_frequency_validation() {
        valid = false;
        band = "";
        mode = "";
        error_message = "";
        channel_spacing = 0.0;
    }
};

// Amateur radio utility functions
class FGCom_AmateurRadio {
private:
    static std::vector<fgcom_band_segment> band_segments;
    static std::map<std::string, fgcom_band_characteristics> band_characteristics;
    static std::vector<fgcom_itu_region> itu_regions;
    static bool initialized;
    
public:
    // Initialize amateur radio data
    static bool initialize();
    
    // Load band segments from CSV file
    static bool loadBandSegments(const std::string& csv_file);
    
    // Auto-detect ITU region based on coordinates
    static int detectITURegion(double lat, double lon);
    
    // Validate frequency and mode for amateur radio
    static bool validateAmateurFrequency(const std::string& frequency, const std::string& mode, int itu_region);
    
    // Enhanced frequency validation with detailed results
    static fgcom_frequency_validation validateFrequencyDetailed(const std::string& frequency, const std::string& mode, int itu_region);
    
    // Check band compliance (prevent out-of-band operation)
    static bool checkBandCompliance(float frequency_khz, const std::string& mode, int itu_region);
    
    // Enforce mode separation (CW/SSB frequency allocation)
    static bool enforceModeSeparation(float frequency_khz, const std::string& mode, int itu_region);
    
    // Handle regional restrictions (60m band limitations)
    static bool checkRegionalRestrictions(float frequency_khz, int itu_region);
    
    // Validate channel spacing (3kHz SSB, 500Hz CW)
    static bool validateChannelSpacing(float frequency_khz, const std::string& mode);
    
    // Get band segment for a given frequency and region
    static fgcom_band_segment getBandSegment(float frequency_khz, int itu_region);
    
    // Get band characteristics
    static fgcom_band_characteristics getBandCharacteristics(const std::string& band);
    
    // Convert frequency to band name
    static std::string frequencyToBand(float frequency_khz);
    
    // Check if frequency is in amateur band
    static bool isAmateurFrequency(float frequency_khz, int itu_region);
    
    // Get all available bands for a region
    static std::vector<std::string> getAvailableBands(int itu_region);
    
    // Get modes available for a band in a region
    static std::vector<std::string> getAvailableModes(const std::string& band, int itu_region);
    
    // Maidenhead Grid Locator functions
    static fgcom_grid_locator parseGridLocator(const std::string& grid_string);
    static std::string gridToLatLon(const std::string& grid, double& lat, double& lon);
    static std::string latLonToGrid(double lat, double lon, int precision = 4);
    static double gridDistance(const std::string& grid1, const std::string& grid2);
    static double gridBearing(const std::string& grid1, const std::string& grid2);
    static bool validateGridLocator(const std::string& grid);
};

#endif // FGCOM_AMATEUR_RADIO_H

