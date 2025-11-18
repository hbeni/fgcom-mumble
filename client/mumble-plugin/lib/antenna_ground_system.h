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

#ifndef FGCOM_ANTENNA_GROUND_SYSTEM_H
#define FGCOM_ANTENNA_GROUND_SYSTEM_H

#include <string>
#include <vector>
#include <map>
#include <complex>
#include "radio_model.h"

// Ground system types and characteristics
struct GroundSystem {
    std::string type;               // "star_network", "copper_plate", "fuselage", "vehicle"
    float conductivity;             // Ground conductivity in S/m
    float area_coverage;           // Coverage area in square meters
    bool is_saltwater;             // Saltwater ground effects
    float depth;                   // Ground system depth in meters
    int radial_count;              // Number of radials (for star networks)
    float radial_length;           // Radial length in meters
    float ground_resistance;       // Ground resistance in ohms
    std::string material;          // Ground system material
    std::string notes;             // Additional information
    
    GroundSystem() {
        type = "average";
        conductivity = 0.01;       // Average soil conductivity
        area_coverage = 100.0;     // 100 m² default
        is_saltwater = false;
        depth = 0.1;               // 10cm burial depth
        radial_count = 16;         // 16 radials default
        radial_length = 10.0;      // 10m radial length
        ground_resistance = 1.0;   // 1 ohm default
        material = "copper";
        notes = "";
    }
};

// 4NEC2 antenna pattern data structure
struct AntennaPattern {
    std::string antenna_name;      // Antenna model name
    float frequency_mhz;           // Frequency in MHz
    std::string polarization;      // "vertical", "horizontal", "circular"
    std::vector<float> theta_angles;  // Elevation angles (degrees)
    std::vector<float> phi_angles;    // Azimuth angles (degrees)
    std::vector<float> gain_dbi;      // Gain values in dBi
    std::vector<float> phase_deg;     // Phase values in degrees
    std::vector<std::complex<float>> e_theta;  // Theta component
    std::vector<std::complex<float>> e_phi;    // Phi component
    bool is_loaded;                // Whether pattern data is loaded
    
    AntennaPattern() {
        antenna_name = "";
        frequency_mhz = 0.0;
        polarization = "vertical";
        is_loaded = false;
    }
};

// Antenna system configuration
struct AntennaSystem {
    std::string antenna_type;      // "dipole", "yagi", "vertical", "whip", "custom"
    float height_meters;           // Antenna height above ground
    float azimuth_deg;             // Azimuth orientation
    float elevation_deg;           // Elevation angle
    GroundSystem ground_system;    // Ground system characteristics
    AntennaPattern pattern;        // 4NEC2 pattern data
    std::string pattern_file;      // Path to 4NEC2 pattern file
    float efficiency;              // Antenna efficiency (0.0-1.0)
    float swr;                     // Standing wave ratio
    float feedpoint_impedance;     // Feedpoint impedance in ohms
    
    AntennaSystem() {
        antenna_type = "vertical";
        height_meters = 10.0;      // 10m default height
        azimuth_deg = 0.0;         // North
        elevation_deg = 0.0;       // Horizontal
        efficiency = 0.8;          // 80% efficiency
        swr = 1.5;                 // 1.5:1 SWR
        feedpoint_impedance = 50.0; // 50 ohm impedance
    }
};

// Ground system performance categories
enum class GroundPerformance {
    EXCELLENT,    // <0.1 Ω resistance, >10 S/m conductivity
    GOOD,         // 0.1-0.5 Ω resistance, 1-10 S/m conductivity
    AVERAGE,      // 0.5-2 Ω resistance, 0.01-1 S/m conductivity
    POOR          // >2 Ω resistance, <0.001 S/m conductivity
};

// Antenna ground system utility class
class FGCom_AntennaGroundSystem {
private:
    static std::map<std::string, GroundSystem> predefined_ground_systems;
    static std::map<std::string, AntennaPattern> antenna_patterns;
    static std::string pattern_directory;
    static bool initialized;
    
public:
    // Initialize ground system data
    static bool initialize();
    static void setPatternDirectory(const std::string& dir);
    
    // Ground system management
    static GroundSystem createGroundSystem(const std::string& type, float conductivity, float area);
    static GroundSystem getPredefinedGroundSystem(const std::string& name);
    static std::vector<std::string> getAvailableGroundSystems();
    
    // Ground system performance calculations
    static GroundPerformance evaluateGroundPerformance(const GroundSystem& ground);
    static float calculateGroundLoss(const GroundSystem& ground, float frequency_mhz);
    static float calculateGroundResistance(const GroundSystem& ground);
    static float calculateGroundConductivity(const GroundSystem& ground);
    
    // Star-shaped wire network calculations
    static GroundSystem createStarNetwork(int radials, float length, float conductivity);
    static float calculateStarNetworkResistance(int radials, float length, float conductivity);
    static float calculateOptimalRadialLength(float frequency_mhz);
    
    // Copper plate calculations
    static GroundSystem createCopperPlate(float area, float conductivity, bool saltwater);
    static float calculatePlateResistance(float area, float conductivity);
    static float calculatePlateCapacitance(float area, float depth);
    
    // Vehicle fuselage calculations
    static GroundSystem createFuselageGround(const std::string& vehicle_type, float area);
    static GroundSystem createAircraftFuselage(const std::string& aircraft_type);
    static GroundSystem createMaritimeVessel(const std::string& vessel_type, float hull_area);
    static float calculateFuselageResistance(float area, const std::string& material);
    
    // Antenna pattern management
    static bool loadAntennaPattern(const std::string& pattern_file);
    static bool load4NEC2Pattern(const std::string& filename);
    static AntennaPattern getAntennaPattern(const std::string& antenna_name, float frequency_mhz);
    static std::vector<std::string> getAvailablePatterns();
    
    // Antenna pattern calculations
    static float getAntennaGain(const AntennaPattern& pattern, float azimuth_deg, float elevation_deg);
    static float getAntennaGain(const AntennaSystem& antenna, float azimuth_deg, float elevation_deg);
    static float calculateAntennaEfficiency(const AntennaSystem& antenna, float frequency_mhz);
    
    // Dipole antenna ground effects
    static float calculateDipoleGroundEffect(const AntennaSystem& antenna, float frequency_mhz);
    static float calculateHorizontalDipoleHeightEffect(float height_meters, float frequency_mhz);
    static float calculateVerticalDipoleGroundEffect(const GroundSystem& ground, float frequency_mhz);
    
    // Yagi antenna ground effects
    static float calculateYagiGroundEffect(const AntennaSystem& antenna, float frequency_mhz);
    static float calculateYagiHeightEffect(float height_meters, float frequency_mhz);
    static float calculateYagiPatternDistortion(float height_meters, float frequency_mhz);
    
    // Whip antenna calculations
    static float calculateWhipEfficiency(const AntennaSystem& antenna, float frequency_mhz);
    static float calculateWhipGroundEffect(const GroundSystem& ground, float frequency_mhz);
    static float calculateWhipImpedance(float length_meters, float frequency_mhz);
    
    // Overall antenna system performance
    static float calculateSystemGain(const AntennaSystem& antenna, float azimuth_deg, float elevation_deg, float frequency_mhz);
    static float calculateSystemLoss(const AntennaSystem& antenna, float frequency_mhz);
    static float calculateEffectiveRadiatedPower(float tx_power_watts, const AntennaSystem& antenna, float azimuth_deg, float elevation_deg, float frequency_mhz);
    
private:
    // Internal helper functions
    static void setupPredefinedGroundSystems();
    static bool parse4NEC2File(const std::string& filename, AntennaPattern& pattern);
    static float interpolatePattern(const AntennaPattern& pattern, float azimuth_deg, float elevation_deg);
    static float calculateGroundReflectionCoefficient(const GroundSystem& ground, float frequency_mhz, float angle_deg);
    static float calculateGroundWaveAttenuation(const GroundSystem& ground, float frequency_mhz, float distance_km);
};

// Configuration management for antenna systems
class FGCom_AntennaConfig {
private:
    static std::map<std::string, std::string> config_values;
    static bool config_loaded;
    
public:
    // Configuration management
    static bool loadConfig(const std::string& config_file);
    static bool saveConfig(const std::string& config_file);
    static std::string getConfigValue(const std::string& key, const std::string& default_value = "");
    static void setConfigValue(const std::string& key, const std::string& value);
    
    // Antenna system configuration
    static AntennaSystem getDefaultAntennaSystem();
    static GroundSystem getDefaultGroundSystem();
    static std::string getPatternDirectory();
    static bool is4NEC2Enabled();
    static bool isGPUAccelerationEnabled();
    
    // Propagation configuration
    static bool isMUFEnabled();
    static bool isSolarEffectsEnabled();
    static bool isSeasonalVariationsEnabled();
    static bool isPropagationCacheEnabled();
    
    // Amateur radio configuration
    static bool isAmateurRadioEnabled();
    static int getITURegion();
    static bool isStrictBandCompliance();
    static float getDefaultPower();
    static float getAntennaHeight();
    
    // Solar data configuration
    static std::string getNOAAAPIURL();
    static int getUpdateInterval();
    static std::string getFallbackDataPath();
    
private:
    static void setDefaultConfig();
    static std::string trimString(const std::string& str);
    static std::vector<std::string> splitString(const std::string& str, char delimiter);
};

#endif // FGCOM_ANTENNA_GROUND_SYSTEM_H
