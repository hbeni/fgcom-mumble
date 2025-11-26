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
// CRITICAL: This structure must match the CSV format exactly: Band,Mode,StartFreq,EndFreq,Region,Country,LicenseClass,PowerLimit,Notes
// Any deviation will cause CSV parsing to fail or assign wrong values to fields!
// The CSV file contains 280+ frequency allocations with country-specific regulations
struct fgcom_band_segment {
    std::string band;           // Amateur radio band designation (e.g., "160m", "80m", "40m", "20m", "15m", "10m", "6m", "2m", "70cm")
    std::string mode;           // Operating mode (e.g., "CW", "SSB", "Digital", "EME", "MS") - must match CSV exactly
    float start_freq;           // Start frequency in kHz (e.g., 1810.0 for 160m CW) - CRITICAL: Must be < end_freq
    float end_freq;             // End frequency in kHz (e.g., 1838.0 for 160m CW) - CRITICAL: Must be > start_freq
    int itu_region;             // ITU Region (1=Europe/Africa, 2=Americas, 3=Asia-Pacific) - CRITICAL: Must be 1, 2, or 3
    std::string countries;      // Countries/regions for this allocation (e.g., "UK", "USA", "Germany") - used for country-specific validation
    std::string license_class;  // License class required (e.g., "Full", "Intermediate", "Foundation", "Extra", "Advanced", "General") - determines access rights
    float power_limit;          // Power limit in Watts (e.g., 1000.0, 400.0, 1500.0) - CRITICAL: Must be positive, used for power validation
    std::string notes;          // Additional notes/restrictions (e.g., "CW only below 1840 kHz", "Limited to 5 channels") - provides context for restrictions
    
    fgcom_band_segment() {
        // Initialize with safe default values to prevent undefined behavior
        // CRITICAL: These defaults must be valid to prevent validation errors
        band = "";              // Empty string indicates no band assigned
        mode = "";              // Empty string indicates no mode assigned
        start_freq = 0.0;       // Zero frequency indicates invalid allocation
        end_freq = 0.0;         // Zero frequency indicates invalid allocation
        itu_region = 1;         // Default to Region 1 (Europe/Africa) - most restrictive
        countries = "";          // Empty string indicates no country assigned
        license_class = "";     // Empty string indicates no license class assigned
        power_limit = 400.0;    // Default 400W power limit (common for intermediate licenses)
        notes = "";             // Empty string indicates no restrictions
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
    // Initialize amateur radio data from CSV file
    // CRITICAL: Must be called before any other operations to load band segments
    // Returns true if initialization successful, false if CSV file cannot be loaded
    // This loads 280+ frequency allocations from radio_amateur_band_segments.csv
    static bool initialize();
    
    // Load band segments from CSV file with comprehensive validation
    // CRITICAL: CSV format must be exactly: Band,Mode,StartFreq,EndFreq,Region,Country,LicenseClass,PowerLimit,Notes
    // Any deviation will cause parsing to fail or assign wrong values to fields!
    // Returns true if CSV loaded successfully, false if file cannot be opened or parsed
    static bool loadBandSegments(const std::string& csv_file);
    
    // Auto-detect ITU region based on geographic coordinates
    // CRITICAL: Returns 1, 2, or 3 - any other value indicates invalid coordinates
    // Region 1: Europe, Africa, Middle East, former USSR (longitude 40°E to 180°E)
    // Region 2: Americas (longitude 180°W to 20°W)
    // Region 3: Asia-Pacific (longitude 40°E to 180°E, excluding Region 1)
    static int detectITURegion(double lat, double lon);
    
    // Validate frequency and mode for amateur radio compliance
    // CRITICAL: Returns true only if frequency is within valid amateur band for given mode and region
    // This prevents out-of-band operation and ensures regulatory compliance
    // Returns false if frequency is not in amateur bands or mode is not allowed
    static bool validateAmateurFrequency(const std::string& frequency, const std::string& mode, int itu_region);
    
    // Enhanced frequency validation with detailed results
    static fgcom_frequency_validation validateFrequencyDetailed(const std::string& frequency, const std::string& mode, int itu_region);
    
    // Check band compliance (prevent out-of-band operation)
    static bool checkBandCompliance(float frequency_khz, const std::string& mode, int itu_region);
    
    // Enforce mode separation (CW/SSB frequency allocation)
    static bool enforceModeSeparation(float frequency_khz, const std::string& mode, int itu_region);
    
    // Handle regional restrictions (60m band limitations)
    static bool checkRegionalRestrictions(float frequency_khz, int itu_region);
    
    // Check power limit for a given frequency and region
    static float getPowerLimit(float frequency_khz, int itu_region, const std::string& mode);
    
    // Get band segment information for a frequency
    static fgcom_band_segment getBandSegmentInfo(float frequency_khz, int itu_region, const std::string& mode);
    
    // Validate power level against band limits
    static bool validatePowerLevel(float frequency_khz, int itu_region, const std::string& mode, float power_watts);
    
    // Get license class requirements for a frequency and region
    static std::string getRequiredLicenseClass(float frequency_khz, int itu_region, const std::string& mode);
    
    // Get country-specific allocations
    static std::vector<fgcom_band_segment> getCountryAllocations(const std::string& country, int itu_region);
    
    // Check if a license class can operate on a frequency
    static bool canLicenseClassOperate(float frequency_khz, int itu_region, const std::string& mode, const std::string& license_class);
    
    // Get all available bands for a license class and region
    static std::vector<std::string> getAvailableBands(const std::string& license_class, int itu_region);
    
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

