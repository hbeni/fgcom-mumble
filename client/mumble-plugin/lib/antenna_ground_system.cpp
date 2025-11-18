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

#include "antenna_ground_system.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <complex>

// Static member definitions
std::map<std::string, GroundSystem> FGCom_AntennaGroundSystem::predefined_ground_systems;
std::map<std::string, AntennaPattern> FGCom_AntennaGroundSystem::antenna_patterns;
std::string FGCom_AntennaGroundSystem::pattern_directory = "/usr/share/fgcom-mumble/antenna_patterns/";
bool FGCom_AntennaGroundSystem::initialized = false;

std::map<std::string, std::string> FGCom_AntennaConfig::config_values;
bool FGCom_AntennaConfig::config_loaded = false;

bool FGCom_AntennaGroundSystem::initialize() {
    if (initialized) return true;
    
    setupPredefinedGroundSystems();
    initialized = true;
    return true;
}

void FGCom_AntennaGroundSystem::setPatternDirectory(const std::string& dir) {
    pattern_directory = dir;
}

void FGCom_AntennaGroundSystem::setupPredefinedGroundSystems() {
    // Excellent ground systems
    GroundSystem excellent_star;
    excellent_star.type = "star_network";
    excellent_star.conductivity = 15.0;      // Saltwater coastal
    excellent_star.area_coverage = 3000.0;   // >2000 m²
    excellent_star.radial_count = 64;        // 60+ radials
    excellent_star.radial_length = 25.0;     // λ/4 at HF
    excellent_star.ground_resistance = 0.05; // <0.1 Ω
    excellent_star.is_saltwater = true;
    excellent_star.material = "copper";
    excellent_star.notes = "Excellent star network for coastal HF station";
    predefined_ground_systems["excellent_star"] = excellent_star;
    
    GroundSystem excellent_plate;
    excellent_plate.type = "copper_plate";
    excellent_plate.conductivity = 5.0;      // Saltwater environment
    excellent_plate.area_coverage = 100.0;   // >50 m²
    excellent_plate.ground_resistance = 0.02; // <0.1 Ω
    excellent_plate.is_saltwater = true;
    excellent_plate.material = "copper";
    excellent_plate.notes = "Large copper plate in saltwater";
    predefined_ground_systems["excellent_plate"] = excellent_plate;
    
    // Good ground systems
    GroundSystem good_star;
    good_star.type = "star_network";
    good_star.conductivity = 5.0;            // Average soil
    good_star.area_coverage = 1500.0;        // 500-2000 m²
    good_star.radial_count = 32;             // 16-32 radials
    good_star.radial_length = 15.0;          // λ/8 to λ/4
    good_star.ground_resistance = 0.3;       // 0.1-0.5 Ω
    good_star.is_saltwater = false;
    good_star.material = "copper";
    good_star.notes = "Good star network for inland HF station";
    predefined_ground_systems["good_star"] = good_star;
    
    GroundSystem good_plate;
    good_plate.type = "copper_plate";
    good_plate.conductivity = 0.5;           // Freshwater or moderate soil
    good_plate.area_coverage = 30.0;         // 10-50 m²
    good_plate.ground_resistance = 0.2;      // 0.1-0.5 Ω
    good_plate.is_saltwater = false;
    good_plate.material = "copper";
    good_plate.notes = "Good copper plate for freshwater/moderate soil";
    predefined_ground_systems["good_plate"] = good_plate;
    
    // Average ground systems
    GroundSystem average_star;
    average_star.type = "star_network";
    average_star.conductivity = 0.1;         // Average soil
    average_star.area_coverage = 800.0;      // 500-2000 m²
    average_star.radial_count = 16;          // 16-32 radials
    average_star.radial_length = 10.0;       // λ/8 to λ/4
    average_star.ground_resistance = 1.0;    // 0.5-2 Ω
    average_star.is_saltwater = false;
    average_star.material = "copper";
    average_star.notes = "Average star network for typical soil";
    predefined_ground_systems["average_star"] = average_star;
    
    GroundSystem average_plate;
    average_plate.type = "copper_plate";
    average_plate.conductivity = 0.01;       // Poor soil
    average_plate.area_coverage = 5.0;       // <10 m²
    average_plate.ground_resistance = 1.5;   // 0.5-2 Ω
    average_plate.is_saltwater = false;
    average_plate.material = "copper";
    average_plate.notes = "Average copper plate for poor soil";
    predefined_ground_systems["average_plate"] = average_plate;
    
    // Poor ground systems
    GroundSystem poor_star;
    poor_star.type = "star_network";
    poor_star.conductivity = 0.0001;         // Dry sand, rocky terrain
    poor_star.area_coverage = 200.0;         // <500 m²
    poor_star.radial_count = 8;              // <16 radials
    poor_star.radial_length = 5.0;           // Very short radials
    poor_star.ground_resistance = 5.0;       // >2 Ω
    poor_star.is_saltwater = false;
    poor_star.material = "aluminum";
    poor_star.notes = "Poor star network for dry/rocky terrain";
    predefined_ground_systems["poor_star"] = poor_star;
    
    GroundSystem poor_plate;
    poor_plate.type = "copper_plate";
    poor_plate.conductivity = 0.0001;        // Very poor conductivity
    poor_plate.area_coverage = 2.0;          // <10 m²
    poor_plate.ground_resistance = 10.0;     // >2 Ω
    poor_plate.is_saltwater = false;
    poor_plate.material = "steel";
    poor_plate.notes = "Poor copper plate for very poor soil";
    predefined_ground_systems["poor_plate"] = poor_plate;
    
    // Aircraft fuselage ground systems
    GroundSystem large_aircraft;
    large_aircraft.type = "fuselage";
    large_aircraft.conductivity = 3.5e7;     // Aluminum conductivity
    large_aircraft.area_coverage = 600.0;    // 500-800 m² effective area
    large_aircraft.ground_resistance = 0.05; // <0.1 Ω
    large_aircraft.is_saltwater = false;
    large_aircraft.material = "aluminum";
    large_aircraft.notes = "Large aircraft (747, A380) fuselage";
    predefined_ground_systems["large_aircraft"] = large_aircraft;
    
    GroundSystem medium_aircraft;
    medium_aircraft.type = "fuselage";
    medium_aircraft.conductivity = 3.5e7;    // Aluminum conductivity
    medium_aircraft.area_coverage = 300.0;   // 200-400 m² effective area
    medium_aircraft.ground_resistance = 0.2; // 0.1-0.5 Ω
    medium_aircraft.is_saltwater = false;
    medium_aircraft.material = "aluminum";
    medium_aircraft.notes = "Medium aircraft (737, A320) fuselage";
    predefined_ground_systems["medium_aircraft"] = medium_aircraft;
    
    GroundSystem small_aircraft;
    small_aircraft.type = "fuselage";
    small_aircraft.conductivity = 3.5e7;     // Aluminum conductivity
    small_aircraft.area_coverage = 100.0;    // 50-150 m² effective area
    small_aircraft.ground_resistance = 1.0;  // 0.5-2 Ω
    small_aircraft.is_saltwater = false;
    small_aircraft.material = "aluminum";
    small_aircraft.notes = "Small aircraft (Cessna 172) fuselage";
    predefined_ground_systems["small_aircraft"] = small_aircraft;
    
    // Maritime vessel ground systems
    GroundSystem large_ship;
    large_ship.type = "fuselage";
    large_ship.conductivity = 5.0;           // Saltwater conductivity
    large_ship.area_coverage = 2000.0;       // 1000+ m² hull area
    large_ship.ground_resistance = 0.005;    // <0.01 Ω
    large_ship.is_saltwater = true;
    large_ship.material = "steel";
    large_ship.notes = "Large ship hull in saltwater";
    predefined_ground_systems["large_ship"] = large_ship;
    
    GroundSystem medium_ship;
    medium_ship.type = "fuselage";
    medium_ship.conductivity = 5.0;          // Saltwater conductivity
    medium_ship.area_coverage = 500.0;       // 100-1000 m²
    medium_ship.ground_resistance = 0.05;    // 0.01-0.1 Ω
    medium_ship.is_saltwater = true;
    medium_ship.material = "steel";
    medium_ship.notes = "Medium ship/boat hull in saltwater";
    predefined_ground_systems["medium_ship"] = medium_ship;
    
    GroundSystem small_boat;
    small_boat.type = "fuselage";
    small_boat.conductivity = 5.0;           // Saltwater conductivity
    small_boat.area_coverage = 50.0;         // 20-100 m²
    small_boat.ground_resistance = 0.5;      // 0.1-1 Ω
    small_boat.is_saltwater = true;
    small_boat.material = "fiberglass";
    small_boat.notes = "Small boat hull in saltwater";
    predefined_ground_systems["small_boat"] = small_boat;
}

GroundSystem FGCom_AntennaGroundSystem::createGroundSystem(const std::string& type, float conductivity, float area) {
    GroundSystem ground;
    ground.type = type;
    ground.conductivity = conductivity;
    ground.area_coverage = area;
    ground.ground_resistance = calculateGroundResistance(ground);
    return ground;
}

GroundSystem FGCom_AntennaGroundSystem::getPredefinedGroundSystem(const std::string& name) {
    if (!initialized) initialize();
    
    auto it = predefined_ground_systems.find(name);
    if (it != predefined_ground_systems.end()) {
        return it->second;
    }
    
    // Return default average ground system if not found
    return predefined_ground_systems["average_star"];
}

std::vector<std::string> FGCom_AntennaGroundSystem::getAvailableGroundSystems() {
    if (!initialized) initialize();
    
    std::vector<std::string> systems;
    for (const auto& pair : predefined_ground_systems) {
        systems.push_back(pair.first);
    }
    return systems;
}

GroundPerformance FGCom_AntennaGroundSystem::evaluateGroundPerformance(const GroundSystem& ground) {
    if (ground.ground_resistance < 0.1 && ground.conductivity > 10.0) {
        return GroundPerformance::EXCELLENT;
    } else if (ground.ground_resistance < 0.5 && ground.conductivity > 1.0) {
        return GroundPerformance::GOOD;
    } else if (ground.ground_resistance < 2.0 && ground.conductivity > 0.01) {
        return GroundPerformance::AVERAGE;
    } else {
        return GroundPerformance::POOR;
    }
}

float FGCom_AntennaGroundSystem::calculateGroundLoss(const GroundSystem& ground, float frequency_mhz) {
    float loss_db = 0.0;
    
    // Ground resistance loss
    if (ground.ground_resistance > 0.1) {
        loss_db += 20.0 * log10(1.0 + ground.ground_resistance);
    }
    
    // Conductivity loss
    if (ground.conductivity < 0.01) {
        loss_db += 6.0; // 6 dB loss for poor conductivity
    } else if (ground.conductivity < 0.1) {
        loss_db += 3.0; // 3 dB loss for moderate conductivity
    }
    
    // Frequency-dependent loss
    if (frequency_mhz < 5.0) {
        loss_db += 2.0; // Additional loss at lower frequencies
    }
    
    return loss_db;
}

float FGCom_AntennaGroundSystem::calculateGroundResistance(const GroundSystem& ground) {
    if (ground.type == "star_network") {
        return calculateStarNetworkResistance(ground.radial_count, ground.radial_length, ground.conductivity);
    } else if (ground.type == "copper_plate") {
        return calculatePlateResistance(ground.area_coverage, ground.conductivity);
    } else if (ground.type == "fuselage") {
        return calculateFuselageResistance(ground.area_coverage, ground.material);
    }
    
    return 1.0; // Default resistance
}

float FGCom_AntennaGroundSystem::calculateGroundConductivity(const GroundSystem& ground) {
    // Calculate effective conductivity based on ground system type
    float base_conductivity = ground.conductivity;
    
    if (ground.is_saltwater) {
        base_conductivity *= 5.0; // Saltwater enhancement
    }
    
    if (ground.type == "star_network") {
        // Star network improves effective conductivity
        base_conductivity *= (1.0 + ground.radial_count / 100.0);
    }
    
    return base_conductivity;
}

GroundSystem FGCom_AntennaGroundSystem::createStarNetwork(int radials, float length, float conductivity) {
    GroundSystem ground;
    ground.type = "star_network";
    ground.radial_count = radials;
    ground.radial_length = length;
    ground.conductivity = conductivity;
    ground.area_coverage = radials * length * length * 0.1; // Approximate coverage
    ground.ground_resistance = calculateStarNetworkResistance(radials, length, conductivity);
    ground.material = "copper";
    return ground;
}

float FGCom_AntennaGroundSystem::calculateStarNetworkResistance(int radials, float length, float conductivity) {
    // Simplified star network resistance calculation
    float single_radial_resistance = 1.0 / (conductivity * length * 0.001); // 1mm wire
    return single_radial_resistance / radials;
}

float FGCom_AntennaGroundSystem::calculateOptimalRadialLength(float frequency_mhz) {
    // Optimal radial length is λ/4 at operating frequency
    float wavelength_m = 300.0 / frequency_mhz; // Wavelength in meters
    return wavelength_m / 4.0;
}

GroundSystem FGCom_AntennaGroundSystem::createCopperPlate(float area, float conductivity, bool saltwater) {
    GroundSystem ground;
    ground.type = "copper_plate";
    ground.area_coverage = area;
    ground.conductivity = conductivity;
    ground.is_saltwater = saltwater;
    ground.ground_resistance = calculatePlateResistance(area, conductivity);
    ground.material = "copper";
    return ground;
}

float FGCom_AntennaGroundSystem::calculatePlateResistance(float area, float conductivity) {
    // Plate resistance calculation
    return 1.0 / (conductivity * area);
}

float FGCom_AntennaGroundSystem::calculatePlateCapacitance(float area, float depth) {
    // Plate capacitance calculation
    const float epsilon_0 = 8.854e-12; // Permittivity of free space
    const float epsilon_r = 10.0;      // Relative permittivity of soil
    return (epsilon_0 * epsilon_r * area) / depth;
}

GroundSystem FGCom_AntennaGroundSystem::createFuselageGround(const std::string& vehicle_type, float area) {
    GroundSystem ground;
    ground.type = "fuselage";
    ground.area_coverage = area;
    
    if (vehicle_type == "aircraft") {
        ground.conductivity = 3.5e7; // Aluminum conductivity
        ground.material = "aluminum";
    } else if (vehicle_type == "ship") {
        ground.conductivity = 5.0; // Saltwater conductivity
        ground.material = "steel";
        ground.is_saltwater = true;
    } else {
        ground.conductivity = 1.0; // Default
        ground.material = "steel";
    }
    
    ground.ground_resistance = calculateFuselageResistance(area, ground.material);
    return ground;
}

GroundSystem FGCom_AntennaGroundSystem::createAircraftFuselage(const std::string& aircraft_type) {
    float area = 100.0; // Default small aircraft
    
    if (aircraft_type == "large" || aircraft_type == "747" || aircraft_type == "A380") {
        area = 600.0;
    } else if (aircraft_type == "medium" || aircraft_type == "737" || aircraft_type == "A320") {
        area = 300.0;
    } else if (aircraft_type == "small" || aircraft_type == "C172") {
        area = 100.0;
    }
    
    return createFuselageGround("aircraft", area);
}

GroundSystem FGCom_AntennaGroundSystem::createMaritimeVessel(const std::string& vessel_type, float hull_area) {
    (void)vessel_type; // Suppress unused parameter warning
    return createFuselageGround("ship", hull_area);
}

float FGCom_AntennaGroundSystem::calculateFuselageResistance(float area, const std::string& material) {
    float conductivity = 1.0;
    
    if (material == "aluminum") {
        conductivity = 3.5e7;
    } else if (material == "copper") {
        conductivity = 5.8e7;
    } else if (material == "steel") {
        conductivity = 1.0e7;
    }
    
    return 1.0 / (conductivity * area * 0.001); // Assume 1mm thickness
}

bool FGCom_AntennaGroundSystem::loadAntennaPattern(const std::string& pattern_file) {
    if (!initialized) initialize();
    
    AntennaPattern pattern;
    if (parse4NEC2File(pattern_file, pattern)) {
        std::string key = pattern.antenna_name + "_" + std::to_string(pattern.frequency_mhz);
        antenna_patterns[key] = pattern;
        return true;
    }
    
    return false;
}

bool FGCom_AntennaGroundSystem::load4NEC2Pattern(const std::string& filename) {
    std::string full_path = pattern_directory + filename;
    return loadAntennaPattern(full_path);
}

AntennaPattern FGCom_AntennaGroundSystem::getAntennaPattern(const std::string& antenna_name, float frequency_mhz) {
    if (!initialized) initialize();
    
    std::string key = antenna_name + "_" + std::to_string(frequency_mhz);
    auto it = antenna_patterns.find(key);
    if (it != antenna_patterns.end()) {
        return it->second;
    }
    
    // Return empty pattern if not found
    return AntennaPattern();
}

std::vector<std::string> FGCom_AntennaGroundSystem::getAvailablePatterns() {
    if (!initialized) initialize();
    
    std::vector<std::string> patterns;
    for (const auto& pair : antenna_patterns) {
        patterns.push_back(pair.first);
    }
    return patterns;
}

bool FGCom_AntennaGroundSystem::parse4NEC2File(const std::string& filename, AntennaPattern& pattern) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    bool in_data_section = false;
    
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#' || line[0] == '!') {
            continue;
        }
        
        // Look for frequency information
        if (line.find("FREQUENCY") != std::string::npos) {
            std::istringstream iss(line);
            std::string token;
            while (iss >> token) {
                if (token.find("MHz") != std::string::npos) {
                    pattern.frequency_mhz = std::stof(token);
                    break;
                }
            }
        }
        
        // Look for antenna name
        if (line.find("ANTENNA") != std::string::npos) {
            std::istringstream iss(line);
            std::string token;
            iss >> token; // Skip "ANTENNA"
            if (iss >> token) {
                pattern.antenna_name = token;
            }
        }
        
        // Look for data section
        if (line.find("THETA") != std::string::npos && line.find("PHI") != std::string::npos) {
            in_data_section = true;
            continue;
        }
        
        // Parse data lines
        if (in_data_section) {
            std::istringstream iss(line);
            float theta, phi, gain, phase;
            if (iss >> theta >> phi >> gain >> phase) {
                pattern.theta_angles.push_back(theta);
                pattern.phi_angles.push_back(phi);
                pattern.gain_dbi.push_back(gain);
                pattern.phase_deg.push_back(phase);
            }
        }
    }
    
    pattern.is_loaded = !pattern.theta_angles.empty();
    return pattern.is_loaded;
}

float FGCom_AntennaGroundSystem::getAntennaGain(const AntennaPattern& pattern, float azimuth_deg, float elevation_deg) {
    if (!pattern.is_loaded) {
        return 0.0; // No pattern data
    }
    
    return interpolatePattern(pattern, azimuth_deg, elevation_deg);
}

float FGCom_AntennaGroundSystem::getAntennaGain(const AntennaSystem& antenna, float azimuth_deg, float elevation_deg) {
    if (antenna.pattern.is_loaded) {
        return getAntennaGain(antenna.pattern, azimuth_deg, elevation_deg);
    }
    
    // Use default gain based on antenna type
    if (antenna.antenna_type == "yagi") {
        return 10.0; // 10 dBi typical for Yagi
    } else if (antenna.antenna_type == "dipole") {
        return 2.15; // 2.15 dBi for dipole
    } else if (antenna.antenna_type == "vertical") {
        return 0.0; // 0 dBi for vertical
    } else if (antenna.antenna_type == "whip") {
        return -3.0; // -3 dBi for whip
    }
    
    return 0.0; // Default
}

float FGCom_AntennaGroundSystem::interpolatePattern(const AntennaPattern& pattern, float azimuth_deg, float elevation_deg) {
    if (pattern.theta_angles.empty()) {
        return 0.0;
    }
    
    // Simple nearest neighbor interpolation
    float min_distance = 1000.0;
    float best_gain = 0.0;
    
    for (size_t i = 0; i < pattern.theta_angles.size(); i++) {
        float theta_diff = std::abs(pattern.theta_angles[i] - elevation_deg);
        float phi_diff = std::abs(pattern.phi_angles[i] - azimuth_deg);
        float distance = sqrt(theta_diff * theta_diff + phi_diff * phi_diff);
        
        if (distance < min_distance) {
            min_distance = distance;
            best_gain = pattern.gain_dbi[i];
        }
    }
    
    return best_gain;
}

float FGCom_AntennaGroundSystem::calculateDipoleGroundEffect(const AntennaSystem& antenna, float frequency_mhz) {
    float effect = 1.0;
    
    if (antenna.antenna_type == "dipole") {
        // Height effect
        float wavelength = 300.0 / frequency_mhz;
        float height_factor = antenna.height_meters / wavelength;
        
        if (height_factor < 0.25) {
            effect *= 0.7; // λ/4 height: strong ground reflection
        } else if (height_factor < 0.5) {
            effect *= 0.8; // λ/2 height: good compromise
        } else {
            effect *= 0.9; // >λ height: multiple lobes
        }
        
        // Ground system effect
        GroundPerformance performance = evaluateGroundPerformance(antenna.ground_system);
        switch (performance) {
            case GroundPerformance::EXCELLENT:
                effect *= 1.0; // No additional loss
                break;
            case GroundPerformance::GOOD:
                effect *= 0.95; // 0.5 dB loss
                break;
            case GroundPerformance::AVERAGE:
                effect *= 0.8; // 2 dB loss
                break;
            case GroundPerformance::POOR:
                effect *= 0.5; // 6 dB loss
                break;
        }
    }
    
    return effect;
}

float FGCom_AntennaGroundSystem::calculateHorizontalDipoleHeightEffect(float height_meters, float frequency_mhz) {
    float wavelength = 300.0 / frequency_mhz;
    float height_factor = height_meters / wavelength;
    
    if (height_factor < 0.25) {
        return 0.7; // 3-6 dB loss, severe nulls
    } else if (height_factor < 0.5) {
        return 0.8; // 1-3 dB loss, moderate
    } else if (height_factor < 1.0) {
        return 0.95; // 0-1 dB loss, minimal
    } else {
        return 1.0; // 0 dB loss, negligible
    }
}

float FGCom_AntennaGroundSystem::calculateVerticalDipoleGroundEffect(const GroundSystem& ground, float frequency_mhz) {
    (void)frequency_mhz; // Suppress unused parameter warning
    GroundPerformance performance = evaluateGroundPerformance(ground);
    
    switch (performance) {
        case GroundPerformance::EXCELLENT:
            return 1.0; // Near-theoretical performance
        case GroundPerformance::GOOD:
            return 0.7; // 3 dB degradation
        case GroundPerformance::AVERAGE:
            return 0.4; // 8 dB degradation
        case GroundPerformance::POOR:
            return 0.1; // 20 dB degradation, high SWR
    }
    
    return 1.0;
}

float FGCom_AntennaGroundSystem::calculateYagiGroundEffect(const AntennaSystem& antenna, float frequency_mhz) {
    float effect = 1.0;
    
    if (antenna.antenna_type == "yagi") {
        // Height effect
        float wavelength = 300.0 / frequency_mhz;
        float height_factor = antenna.height_meters / wavelength;
        
        if (height_factor < 0.5) {
            effect *= 0.7; // 3-6 dB loss, severe nulls
        } else if (height_factor < 1.0) {
            effect *= 0.9; // 1-3 dB loss, moderate
        } else if (height_factor < 1.5) {
            effect *= 0.95; // 0-1 dB loss, minimal
        } else {
            effect *= 1.0; // 0 dB loss, negligible
        }
        
        // Ground system effect
        GroundPerformance performance = evaluateGroundPerformance(antenna.ground_system);
        switch (performance) {
            case GroundPerformance::EXCELLENT:
                effect *= 1.0;
                break;
            case GroundPerformance::GOOD:
                effect *= 0.95;
                break;
            case GroundPerformance::AVERAGE:
                effect *= 0.8;
                break;
            case GroundPerformance::POOR:
                effect *= 0.5;
                break;
        }
    }
    
    return effect;
}

float FGCom_AntennaGroundSystem::calculateYagiHeightEffect(float height_meters, float frequency_mhz) {
    float wavelength = 300.0 / frequency_mhz;
    float height_factor = height_meters / wavelength;
    
    if (height_factor < 0.5) {
        return 0.7; // 3-6 dB loss
    } else if (height_factor < 1.0) {
        return 0.9; // 1-3 dB loss
    } else if (height_factor < 1.5) {
        return 0.95; // 0-1 dB loss
    } else {
        return 1.0; // 0 dB loss
    }
}

float FGCom_AntennaGroundSystem::calculateYagiPatternDistortion(float height_meters, float frequency_mhz) {
    float wavelength = 300.0 / frequency_mhz;
    float height_factor = height_meters / wavelength;
    
    if (height_factor < 0.25) {
        return 0.5; // Severe nulls
    } else if (height_factor < 0.5) {
        return 0.7; // Moderate distortion
    } else if (height_factor < 1.0) {
        return 0.9; // Minimal distortion
    } else {
        return 1.0; // Negligible distortion
    }
}

float FGCom_AntennaGroundSystem::calculateWhipEfficiency(const AntennaSystem& antenna, float frequency_mhz) {
    float efficiency = 0.7; // Base efficiency
    
    // Frequency effect
    float wavelength = 300.0 / frequency_mhz;
    if (wavelength > 10.0) {
        efficiency *= 0.5; // Very long wavelength, poor efficiency
    } else if (wavelength > 5.0) {
        efficiency *= 0.7; // Long wavelength, reduced efficiency
    }
    
    // Ground system effect
    GroundPerformance performance = evaluateGroundPerformance(antenna.ground_system);
    switch (performance) {
        case GroundPerformance::EXCELLENT:
            efficiency *= 1.0;
            break;
        case GroundPerformance::GOOD:
            efficiency *= 0.9;
            break;
        case GroundPerformance::AVERAGE:
            efficiency *= 0.7;
            break;
        case GroundPerformance::POOR:
            efficiency *= 0.5;
            break;
    }
    
    return efficiency;
}

float FGCom_AntennaGroundSystem::calculateWhipGroundEffect(const GroundSystem& ground, float frequency_mhz) {
    return calculateGroundLoss(ground, frequency_mhz) / 10.0; // Convert dB to linear
}

float FGCom_AntennaGroundSystem::calculateWhipImpedance(float length_meters, float frequency_mhz) {
    // Simplified whip impedance calculation
    float wavelength = 300.0 / frequency_mhz;
    float length_factor = length_meters / wavelength;
    
    if (length_factor < 0.25) {
        return 50.0; // Near 50 ohms for short whip
    } else if (length_factor < 0.5) {
        return 75.0; // Higher impedance for longer whip
    } else {
        return 100.0; // High impedance for very long whip
    }
}

float FGCom_AntennaGroundSystem::calculateSystemGain(const AntennaSystem& antenna, float azimuth_deg, float elevation_deg, float frequency_mhz) {
    float gain = getAntennaGain(antenna, azimuth_deg, elevation_deg);
    
    // Apply antenna type specific effects
    if (antenna.antenna_type == "dipole") {
        gain += 10.0 * log10(calculateDipoleGroundEffect(antenna, frequency_mhz));
    } else if (antenna.antenna_type == "yagi") {
        gain += 10.0 * log10(calculateYagiGroundEffect(antenna, frequency_mhz));
    } else if (antenna.antenna_type == "whip") {
        gain += 10.0 * log10(calculateWhipEfficiency(antenna, frequency_mhz));
    }
    
    return gain;
}

float FGCom_AntennaGroundSystem::calculateSystemLoss(const AntennaSystem& antenna, float frequency_mhz) {
    float loss = 0.0;
    
    // Ground system loss
    loss += calculateGroundLoss(antenna.ground_system, frequency_mhz);
    
    // Antenna efficiency loss
    loss += 10.0 * log10(1.0 / antenna.efficiency);
    
    // SWR loss
    loss += 10.0 * log10(antenna.swr);
    
    return loss;
}

float FGCom_AntennaGroundSystem::calculateEffectiveRadiatedPower(float tx_power_watts, const AntennaSystem& antenna, float azimuth_deg, float elevation_deg, float frequency_mhz) {
    float gain_db = calculateSystemGain(antenna, azimuth_deg, elevation_deg, frequency_mhz);
    float loss_db = calculateSystemLoss(antenna, frequency_mhz);
    float net_gain_db = gain_db - loss_db;
    
    return tx_power_watts * pow(10.0, net_gain_db / 10.0);
}

// Configuration management implementation
bool FGCom_AntennaConfig::loadConfig(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        setDefaultConfig();
        return false;
    }
    
    std::string line;
    std::string current_section = "";
    
    while (std::getline(file, line)) {
        line = trimString(line);
        
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        if (line[0] == '[' && line.back() == ']') {
            current_section = line.substr(1, line.length() - 2);
            continue;
        }
        
        size_t equal_pos = line.find('=');
        if (equal_pos != std::string::npos) {
            std::string key = trimString(line.substr(0, equal_pos));
            std::string value = trimString(line.substr(equal_pos + 1));
            
            if (!current_section.empty()) {
                key = current_section + "." + key;
            }
            
            config_values[key] = value;
        }
    }
    
    config_loaded = true;
    return true;
}

bool FGCom_AntennaConfig::saveConfig(const std::string& config_file) {
    std::ofstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    std::string current_section = "";
    
    for (const auto& pair : config_values) {
        size_t dot_pos = pair.first.find('.');
        std::string section = (dot_pos != std::string::npos) ? pair.first.substr(0, dot_pos) : "";
        std::string key = (dot_pos != std::string::npos) ? pair.first.substr(dot_pos + 1) : pair.first;
        
        if (section != current_section) {
            if (!current_section.empty()) {
                file << std::endl;
            }
            file << "[" << section << "]" << std::endl;
            current_section = section;
        }
        
        file << key << "=" << pair.second << std::endl;
    }
    
    return true;
}

std::string FGCom_AntennaConfig::getConfigValue(const std::string& key, const std::string& default_value) {
    if (!config_loaded) {
        setDefaultConfig();
    }
    
    auto it = config_values.find(key);
    if (it != config_values.end()) {
        return it->second;
    }
    
    return default_value;
}

void FGCom_AntennaConfig::setConfigValue(const std::string& key, const std::string& value) {
    config_values[key] = value;
}

AntennaSystem FGCom_AntennaConfig::getDefaultAntennaSystem() {
    AntennaSystem antenna;
    antenna.antenna_type = getConfigValue("antenna_system.default_antenna_type", "vertical");
    antenna.height_meters = std::stof(getConfigValue("antenna_system.default_height", "10.0"));
    antenna.efficiency = std::stof(getConfigValue("antenna_system.default_efficiency", "0.8"));
    antenna.swr = std::stof(getConfigValue("antenna_system.default_swr", "1.5"));
    antenna.feedpoint_impedance = std::stof(getConfigValue("antenna_system.default_impedance", "50.0"));
    return antenna;
}

GroundSystem FGCom_AntennaConfig::getDefaultGroundSystem() {
    std::string ground_type = getConfigValue("antenna_system.default_ground_type", "average");
    return FGCom_AntennaGroundSystem::getPredefinedGroundSystem(ground_type + "_star");
}

std::string FGCom_AntennaConfig::getPatternDirectory() {
    return getConfigValue("antenna_system.pattern_directory", "/usr/share/fgcom-mumble/antenna_patterns/");
}

bool FGCom_AntennaConfig::is4NEC2Enabled() {
    return getConfigValue("antenna_system.enable_4nec2_patterns", "true") == "true";
}

bool FGCom_AntennaConfig::isGPUAccelerationEnabled() {
    return getConfigValue("antenna_system.enable_gpu_acceleration", "false") == "true";
}

bool FGCom_AntennaConfig::isMUFEnabled() {
    return getConfigValue("propagation.enable_muf_luf", "true") == "true";
}

bool FGCom_AntennaConfig::isSolarEffectsEnabled() {
    return getConfigValue("propagation.enable_solar_effects", "true") == "true";
}

bool FGCom_AntennaConfig::isSeasonalVariationsEnabled() {
    return getConfigValue("propagation.enable_seasonal_variations", "true") == "true";
}

bool FGCom_AntennaConfig::isPropagationCacheEnabled() {
    return getConfigValue("propagation.cache_propagation_results", "true") == "true";
}

bool FGCom_AntennaConfig::isAmateurRadioEnabled() {
    return getConfigValue("amateur_radio.enabled", "true") == "true";
}

int FGCom_AntennaConfig::getITURegion() {
    std::string region = getConfigValue("amateur_radio.itu_region", "auto");
    if (region == "auto") {
        return 1; // Default to Region 1
    }
    return std::stoi(region);
}

bool FGCom_AntennaConfig::isStrictBandCompliance() {
    return getConfigValue("amateur_radio.strict_band_compliance", "true") == "true";
}

float FGCom_AntennaConfig::getDefaultPower() {
    return std::stof(getConfigValue("amateur_radio.default_power", "100.0"));
}

float FGCom_AntennaConfig::getAntennaHeight() {
    return std::stof(getConfigValue("amateur_radio.antenna_height", "10.0"));
}

std::string FGCom_AntennaConfig::getNOAAAPIURL() {
    return getConfigValue("solar_data.noaa_api_url", "https://services.swpc.noaa.gov/json/");
}

int FGCom_AntennaConfig::getUpdateInterval() {
    return std::stoi(getConfigValue("solar_data.update_interval", "900"));
}

std::string FGCom_AntennaConfig::getFallbackDataPath() {
    return getConfigValue("solar_data.fallback_data_path", "/usr/share/fgcom-mumble/solar_fallback.json");
}

void FGCom_AntennaConfig::setDefaultConfig() {
    // Amateur radio configuration
    config_values["amateur_radio.enabled"] = "true";
    config_values["amateur_radio.itu_region"] = "auto";
    config_values["amateur_radio.strict_band_compliance"] = "true";
    config_values["amateur_radio.default_power"] = "100";
    config_values["amateur_radio.antenna_height"] = "10";
    
    // Solar data configuration
    config_values["solar_data.noaa_api_url"] = "https://services.swpc.noaa.gov/json/";
    config_values["solar_data.update_interval"] = "900";
    config_values["solar_data.fallback_data_path"] = "/usr/share/fgcom-mumble/solar_fallback.json";
    
    // Propagation configuration
    config_values["propagation.enable_muf_luf"] = "true";
    config_values["propagation.enable_solar_effects"] = "true";
    config_values["propagation.enable_seasonal_variations"] = "true";
    config_values["propagation.cache_propagation_results"] = "true";
    
    // Antenna system configuration
    config_values["antenna_system.enable_4nec2_patterns"] = "true";
    config_values["antenna_system.enable_gpu_acceleration"] = "true";
    config_values["antenna_system.antenna_pattern_cache_size"] = "1000";
    config_values["antenna_system.default_ground_type"] = "average";
    config_values["antenna_system.pattern_directory"] = "/usr/share/fgcom-mumble/antenna_patterns/";
    config_values["antenna_system.default_antenna_type"] = "vertical";
    config_values["antenna_system.default_height"] = "10.0";
    config_values["antenna_system.default_efficiency"] = "0.8";
    config_values["antenna_system.default_swr"] = "1.5";
    config_values["antenna_system.default_impedance"] = "50.0";
    
    config_loaded = true;
}

std::string FGCom_AntennaConfig::trimString(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

std::vector<std::string> FGCom_AntennaConfig::splitString(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(trimString(token));
    }
    
    return tokens;
}
