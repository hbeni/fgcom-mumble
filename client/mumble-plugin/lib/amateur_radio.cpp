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

#include "amateur_radio.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <set>
#include <cctype>

// Static member definitions
std::vector<fgcom_band_segment> FGCom_AmateurRadio::band_segments;
std::map<std::string, fgcom_band_characteristics> FGCom_AmateurRadio::band_characteristics;
std::vector<fgcom_itu_region> FGCom_AmateurRadio::itu_regions;
bool FGCom_AmateurRadio::initialized = false;

bool FGCom_AmateurRadio::initialize() {
    if (initialized) return true;
    
    // Initialize ITU regions
    itu_regions.clear();
    
    // ITU Region 1: Europe, Africa, Middle East, former USSR
    fgcom_itu_region region1;
    region1.region = 1;
    region1.name = "Europe, Africa, Middle East, former USSR";
    region1.min_lat = -90.0; region1.max_lat = 90.0;
    region1.min_lon = -180.0; region1.max_lon = 40.0;
    itu_regions.push_back(region1);
    
    // ITU Region 2: Americas
    fgcom_itu_region region2;
    region2.region = 2;
    region2.name = "Americas";
    region2.min_lat = -90.0; region2.max_lat = 90.0;
    region2.min_lon = -180.0; region2.max_lon = -20.0;
    itu_regions.push_back(region2);
    
    // ITU Region 3: Asia-Pacific
    fgcom_itu_region region3;
    region3.region = 3;
    region3.name = "Asia-Pacific";
    region3.min_lat = -90.0; region3.max_lat = 90.0;
    region3.min_lon = 40.0; region3.max_lon = 180.0;
    itu_regions.push_back(region3);
    
    // Initialize band characteristics
    band_characteristics.clear();
    
    // 160m band characteristics
    fgcom_band_characteristics band160m;
    band160m.band = "160m";
    band160m.center_freq = 1900.0; // kHz
    band160m.wavelength = 160.0;
    band160m.propagation = "Ground wave";
    band160m.max_range_km = 500.0;
    band160m.day_night_factor = 0.3; // Better at night
    band160m.dx_capable = true;
    band_characteristics["160m"] = band160m;
    
    // 80m band characteristics
    fgcom_band_characteristics band80m;
    band80m.band = "80m";
    band80m.center_freq = 3750.0; // kHz
    band80m.wavelength = 80.0;
    band80m.propagation = "Ground wave / Sky wave";
    band80m.max_range_km = 1000.0;
    band80m.day_night_factor = 0.5; // Better at night
    band80m.dx_capable = true;
    band_characteristics["80m"] = band80m;
    
    // 40m band characteristics
    fgcom_band_characteristics band40m;
    band40m.band = "40m";
    band40m.center_freq = 7100.0; // kHz
    band40m.wavelength = 40.0;
    band40m.propagation = "Sky wave";
    band40m.max_range_km = 3000.0;
    band40m.day_night_factor = 0.7; // Good day and night
    band40m.dx_capable = true;
    band_characteristics["40m"] = band40m;
    
    // 20m band characteristics
    fgcom_band_characteristics band20m;
    band20m.band = "20m";
    band20m.center_freq = 14175.0; // kHz
    band20m.wavelength = 20.0;
    band20m.propagation = "Sky wave";
    band20m.max_range_km = 10000.0;
    band20m.day_night_factor = 0.9; // Excellent day band
    band20m.dx_capable = true;
    band_characteristics["20m"] = band20m;
    
    // 10m band characteristics
    fgcom_band_characteristics band10m;
    band10m.band = "10m";
    band10m.center_freq = 28500.0; // kHz
    band10m.wavelength = 10.0;
    band10m.propagation = "Line of sight / Sky wave";
    band10m.max_range_km = 2000.0;
    band10m.day_night_factor = 1.0; // Day band
    band10m.dx_capable = true;
    band_characteristics["10m"] = band10m;
    
    // 6m band characteristics
    fgcom_band_characteristics band6m;
    band6m.band = "6m";
    band6m.center_freq = 52000.0; // kHz
    band6m.wavelength = 6.0;
    band6m.propagation = "Line of sight";
    band6m.max_range_km = 500.0;
    band6m.day_night_factor = 1.0; // Day band
    band6m.dx_capable = false;
    band_characteristics["6m"] = band6m;
    
    // Load band segments from CSV
    if (!loadBandSegments("band_segments.csv")) {
        std::cerr << "Failed to load band segments" << std::endl;
        return false;
    }
    
    initialized = true;
    return true;
}

bool FGCom_AmateurRadio::loadBandSegments(const std::string& csv_file) {
    std::ifstream file(csv_file);
    if (!file.is_open()) {
        std::cerr << "Cannot open band segments file: " << csv_file << std::endl;
        return false;
    }
    
    band_segments.clear();
    std::string line;
    bool first_line = true;
    
    while (std::getline(file, line)) {
        if (first_line) {
            first_line = false;
            continue; // Skip header
        }
        
        if (line.empty()) continue;
        
        std::stringstream ss(line);
        std::string field;
        std::vector<std::string> fields;
        
        // Parse CSV line (simple parsing, doesn't handle quoted fields with commas)
        while (std::getline(ss, field, ',')) {
            fields.push_back(field);
        }
        
        if (fields.size() >= 5) {
            fgcom_band_segment segment;
            segment.band = fields[0];
            segment.mode = fields[1];
            segment.start_freq = std::stof(fields[2]);
            segment.end_freq = std::stof(fields[3]);
            segment.itu_region = std::stoi(fields[4]);
            if (fields.size() > 5) {
                segment.notes = fields[5];
            }
            
            band_segments.push_back(segment);
        }
    }
    
    file.close();
    return true;
}

int FGCom_AmateurRadio::detectITURegion(double lat, double lon) {
    // Normalize longitude to -180 to 180 range
    while (lon > 180.0) lon -= 360.0;
    while (lon < -180.0) lon += 360.0;
    
    // Simple region detection based on longitude
    if (lon >= -180.0 && lon <= -20.0) {
        return 2; // Americas
    } else if (lon >= 40.0 && lon <= 180.0) {
        return 3; // Asia-Pacific
    } else {
        return 1; // Europe, Africa, Middle East, former USSR
    }
}

bool FGCom_AmateurRadio::validateAmateurFrequency(const std::string& frequency, const std::string& mode, int itu_region) {
    if (!initialized) initialize();
    
    float freq_khz = std::stof(frequency);
    
    // Check if frequency is in any amateur band segment for the given region and mode
    for (const auto& segment : band_segments) {
        if (segment.itu_region == itu_region && 
            segment.mode == mode &&
            freq_khz >= segment.start_freq && 
            freq_khz <= segment.end_freq) {
            return true;
        }
    }
    
    return false;
}

fgcom_band_segment FGCom_AmateurRadio::getBandSegment(float frequency_khz, int itu_region) {
    fgcom_band_segment empty_segment;
    
    if (!initialized) initialize();
    
    for (const auto& segment : band_segments) {
        if (segment.itu_region == itu_region &&
            frequency_khz >= segment.start_freq && 
            frequency_khz <= segment.end_freq) {
            return segment;
        }
    }
    
    return empty_segment;
}

fgcom_band_characteristics FGCom_AmateurRadio::getBandCharacteristics(const std::string& band) {
    fgcom_band_characteristics empty_characteristics;
    
    if (!initialized) initialize();
    
    auto it = band_characteristics.find(band);
    if (it != band_characteristics.end()) {
        return it->second;
    }
    
    return empty_characteristics;
}

std::string FGCom_AmateurRadio::frequencyToBand(float frequency_khz) {
    if (!initialized) initialize();
    
    // Determine band based on frequency
    if (frequency_khz >= 1800 && frequency_khz <= 2000) return "160m";
    if (frequency_khz >= 3500 && frequency_khz <= 4000) return "80m";
    if (frequency_khz >= 5300 && frequency_khz <= 5400) return "60m";
    if (frequency_khz >= 7000 && frequency_khz <= 7300) return "40m";
    if (frequency_khz >= 10100 && frequency_khz <= 10150) return "30m";
    if (frequency_khz >= 14000 && frequency_khz <= 14350) return "20m";
    if (frequency_khz >= 18068 && frequency_khz <= 18168) return "17m";
    if (frequency_khz >= 21000 && frequency_khz <= 21450) return "15m";
    if (frequency_khz >= 24890 && frequency_khz <= 24990) return "12m";
    if (frequency_khz >= 28000 && frequency_khz <= 29700) return "10m";
    if (frequency_khz >= 50000 && frequency_khz <= 54000) return "6m";
    
    return "";
}

bool FGCom_AmateurRadio::isAmateurFrequency(float frequency_khz, int itu_region) {
    if (!initialized) initialize();
    
    for (const auto& segment : band_segments) {
        if (segment.itu_region == itu_region &&
            frequency_khz >= segment.start_freq && 
            frequency_khz <= segment.end_freq) {
            return true;
        }
    }
    
    return false;
}

std::vector<std::string> FGCom_AmateurRadio::getAvailableBands(int itu_region) {
    std::vector<std::string> bands;
    
    if (!initialized) initialize();
    
    std::set<std::string> unique_bands;
    for (const auto& segment : band_segments) {
        if (segment.itu_region == itu_region) {
            unique_bands.insert(segment.band);
        }
    }
    
    for (const auto& band : unique_bands) {
        bands.push_back(band);
    }
    
    return bands;
}

std::vector<std::string> FGCom_AmateurRadio::getAvailableModes(const std::string& band, int itu_region) {
    std::vector<std::string> modes;
    
    if (!initialized) initialize();
    
    std::set<std::string> unique_modes;
    for (const auto& segment : band_segments) {
        if (segment.itu_region == itu_region && segment.band == band) {
            unique_modes.insert(segment.mode);
        }
    }
    
    for (const auto& mode : unique_modes) {
        modes.push_back(mode);
    }
    
    return modes;
}

// Enhanced frequency validation with detailed results
fgcom_frequency_validation FGCom_AmateurRadio::validateFrequencyDetailed(const std::string& frequency, const std::string& mode, int itu_region) {
    fgcom_frequency_validation result;
    
    if (!initialized) initialize();
    
    float freq_khz = std::stof(frequency);
    
    // Check band compliance
    if (!checkBandCompliance(freq_khz, mode, itu_region)) {
        result.error_message = "Frequency is outside amateur band limits";
        return result;
    }
    
    // Enforce mode separation
    if (!enforceModeSeparation(freq_khz, mode, itu_region)) {
        result.error_message = "Frequency not allocated for " + mode + " mode in this region";
        return result;
    }
    
    // Check regional restrictions
    if (!checkRegionalRestrictions(freq_khz, itu_region)) {
        result.error_message = "Frequency restricted in this ITU region";
        return result;
    }
    
    // Validate channel spacing
    if (!validateChannelSpacing(freq_khz, mode)) {
        result.error_message = "Invalid channel spacing for " + mode + " mode";
        return result;
    }
    
    // If we get here, frequency is valid
    result.valid = true;
    result.band = frequencyToBand(freq_khz);
    result.mode = mode;
    result.channel_spacing = (mode == "CW") ? 500.0 : 3000.0; // 500Hz for CW, 3kHz for SSB
    
    return result;
}

// Check band compliance (prevent out-of-band operation)
bool FGCom_AmateurRadio::checkBandCompliance(float frequency_khz, const std::string& mode, int itu_region) {
    if (!initialized) initialize();
    
    // Check if frequency is within any amateur band segment for the given region and mode
    for (const auto& segment : band_segments) {
        if (segment.itu_region == itu_region && 
            segment.mode == mode &&
            frequency_khz >= segment.start_freq && 
            frequency_khz <= segment.end_freq) {
            return true;
        }
    }
    
    return false;
}

// Enforce mode separation (CW/SSB frequency allocation)
bool FGCom_AmateurRadio::enforceModeSeparation(float frequency_khz, const std::string& mode, int itu_region) {
    if (!initialized) initialize();
    
    // Get the band segment for this frequency
    fgcom_band_segment segment = getBandSegment(frequency_khz, itu_region);
    
    if (segment.band.empty()) {
        return false; // Not in any amateur band
    }
    
    // Check if the frequency is in the correct mode segment
    for (const auto& seg : band_segments) {
        if (seg.itu_region == itu_region && 
            seg.band == segment.band &&
            seg.mode == mode &&
            frequency_khz >= seg.start_freq && 
            frequency_khz <= seg.end_freq) {
            return true;
        }
    }
    
    return false;
}

// Handle regional restrictions (60m band limitations)
bool FGCom_AmateurRadio::checkRegionalRestrictions(float frequency_khz, int itu_region) {
    if (!initialized) initialize();
    
    // 60m band has special restrictions
    if (frequency_khz >= 5300.0 && frequency_khz <= 5400.0) {
        // 60m band is only available in certain regions and countries
        // This is a simplified check - in practice, you'd need country-specific data
        return true; // For now, allow in all regions
    }
    
    // Other bands don't have regional restrictions beyond ITU region differences
    return true;
}

// Validate channel spacing (3kHz SSB, 500Hz CW)
bool FGCom_AmateurRadio::validateChannelSpacing(float frequency_khz, const std::string& mode) {
    // Check if frequency aligns with proper channel spacing
    float spacing_hz = (mode == "CW") ? 500.0 : 3000.0; // 500Hz for CW, 3kHz for SSB
    float spacing_khz = spacing_hz / 1000.0;
    
    // Check if frequency is on a valid channel
    float remainder = fmod(frequency_khz, spacing_khz);
    return (remainder < 0.001 || remainder > (spacing_khz - 0.001)); // Allow small rounding errors
}

// Maidenhead Grid Locator functions
fgcom_grid_locator FGCom_AmateurRadio::parseGridLocator(const std::string& grid_string) {
    fgcom_grid_locator result;
    result.grid = grid_string;
    
    if (validateGridLocator(grid_string)) {
        result.valid = true;
        gridToLatLon(grid_string, result.lat, result.lon);
    } else {
        result.valid = false;
    }
    
    return result;
}

std::string FGCom_AmateurRadio::gridToLatLon(const std::string& grid, double& lat, double& lon) {
    if (grid.length() < 4) {
        lat = lon = 0.0;
        return "";
    }
    
    // Convert to uppercase
    std::string grid_upper = grid;
    std::transform(grid_upper.begin(), grid_upper.end(), grid_upper.begin(), ::toupper);
    
    // Parse field (first two characters)
    int field_lon = grid_upper[0] - 'A';
    int field_lat = grid_upper[1] - 'A';
    
    // Parse square (next two characters)
    int square_lon = grid_upper[2] - '0';
    int square_lat = grid_upper[3] - '0';
    
    // Calculate base coordinates
    lon = (field_lon * 20.0) + (square_lon * 2.0) - 180.0;
    lat = (field_lat * 10.0) + (square_lat * 1.0) - 90.0;
    
    // Add subsquare precision if available
    if (grid.length() >= 6) {
        double subsquare_lon = (grid_upper[4] - 'A') * (2.0 / 24.0);
        double subsquare_lat = (grid_upper[5] - 'A') * (1.0 / 24.0);
        lon += subsquare_lon;
        lat += subsquare_lat;
    }
    
    // Add extended precision if available
    if (grid.length() >= 8) {
        double extended_lon = (grid_upper[6] - '0') * (2.0 / 240.0);
        double extended_lat = (grid_upper[7] - '0') * (1.0 / 240.0);
        lon += extended_lon;
        lat += extended_lat;
    }
    
    return grid;
}

std::string FGCom_AmateurRadio::latLonToGrid(double lat, double lon, int precision) {
    // Normalize coordinates
    lon += 180.0;
    lat += 90.0;
    
    // Calculate field
    int field_lon = (int)(lon / 20.0);
    int field_lat = (int)(lat / 10.0);
    
    // Calculate square
    int square_lon = (int)((lon - field_lon * 20.0) / 2.0);
    int square_lat = (int)((lat - field_lat * 10.0) / 1.0);
    
    std::string grid = "";
    grid += (char)('A' + field_lon);
    grid += (char)('A' + field_lat);
    grid += (char)('0' + square_lon);
    grid += (char)('0' + square_lat);
    
    if (precision >= 6) {
        // Add subsquare
        double subsquare_lon = (lon - field_lon * 20.0 - square_lon * 2.0) * 12.0;
        double subsquare_lat = (lat - field_lat * 10.0 - square_lat * 1.0) * 24.0;
        grid += (char)('A' + (int)subsquare_lon);
        grid += (char)('A' + (int)subsquare_lat);
    }
    
    if (precision >= 8) {
        // Add extended precision
        double extended_lon = (subsquare_lon - (int)subsquare_lon) * 10.0;
        double extended_lat = (subsquare_lat - (int)subsquare_lat) * 10.0;
        grid += (char)('0' + (int)extended_lon);
        grid += (char)('0' + (int)extended_lat);
    }
    
    return grid;
}

double FGCom_AmateurRadio::gridDistance(const std::string& grid1, const std::string& grid2) {
    double lat1, lon1, lat2, lon2;
    
    gridToLatLon(grid1, lat1, lon1);
    gridToLatLon(grid2, lat2, lon2);
    
    // Calculate distance using Haversine formula
    const double R = 6371.0; // Earth's radius in km
    double dlat = (lat2 - lat1) * M_PI / 180.0;
    double dlon = (lon2 - lon1) * M_PI / 180.0;
    double a = sin(dlat/2) * sin(dlat/2) + cos(lat1 * M_PI / 180.0) * cos(lat2 * M_PI / 180.0) * sin(dlon/2) * sin(dlon/2);
    double c = 2 * atan2(sqrt(a), sqrt(1-a));
    
    return R * c;
}

double FGCom_AmateurRadio::gridBearing(const std::string& grid1, const std::string& grid2) {
    double lat1, lon1, lat2, lon2;
    
    gridToLatLon(grid1, lat1, lon1);
    gridToLatLon(grid2, lat2, lon2);
    
    // Calculate bearing
    double dlon = (lon2 - lon1) * M_PI / 180.0;
    double lat1_rad = lat1 * M_PI / 180.0;
    double lat2_rad = lat2 * M_PI / 180.0;
    
    double y = sin(dlon) * cos(lat2_rad);
    double x = cos(lat1_rad) * sin(lat2_rad) - sin(lat1_rad) * cos(lat2_rad) * cos(dlon);
    
    double bearing = atan2(y, x) * 180.0 / M_PI;
    return fmod(bearing + 360.0, 360.0); // Normalize to 0-360
}

bool FGCom_AmateurRadio::validateGridLocator(const std::string& grid) {
    if (grid.length() < 4 || grid.length() > 8 || grid.length() % 2 != 0) {
        return false;
    }
    
    // Check field characters (A-R)
    if (grid[0] < 'A' || grid[0] > 'R' || grid[1] < 'A' || grid[1] > 'R') {
        return false;
    }
    
    // Check square characters (0-9)
    if (grid[2] < '0' || grid[2] > '9' || grid[3] < '0' || grid[3] > '9') {
        return false;
    }
    
    // Check subsquare characters if present (A-X)
    if (grid.length() >= 6) {
        if (grid[4] < 'A' || grid[4] > 'X' || grid[5] < 'A' || grid[5] > 'X') {
            return false;
        }
    }
    
    // Check extended precision characters if present (0-9)
    if (grid.length() >= 8) {
        if (grid[6] < '0' || grid[6] > '9' || grid[7] < '0' || grid[7] > '9') {
            return false;
        }
    }
    
    return true;
}
