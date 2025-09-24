#include "antenna_pattern_mapping.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <memory>

// Global pattern mapping instance
std::unique_ptr<FGCom_AntennaPatternMapping> g_antenna_pattern_mapping = nullptr;

FGCom_AntennaPatternMapping::FGCom_AntennaPatternMapping() {
    initializeVHFPatterns();
    initializeUHFPatterns();
}

FGCom_AntennaPatternMapping::~FGCom_AntennaPatternMapping() {
    // Cleanup
}

void FGCom_AntennaPatternMapping::initializeVHFPatterns() {
    // Aircraft VHF patterns
    vhf_patterns["aircraft"][150.0] = AntennaPatternInfo(
        "b737_800_vhf", 
        "antenna_patterns/aircraft/b737_800/b737_800_vhf.ez",
        150.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][150.0] = AntennaPatternInfo(
        "c130_hercules_vhf",
        "antenna_patterns/aircraft/c130_hercules/c130_hercules_vhf.ez", 
        150.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][150.0] = AntennaPatternInfo(
        "cessna_172_vhf",
        "antenna_patterns/aircraft/cessna_172/cessna_172_vhf.ez",
        150.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][150.0] = AntennaPatternInfo(
        "mi4_hound_vhf",
        "antenna_patterns/aircraft/mi4_hound/mi4_hound_vhf.ez",
        150.0, "aircraft", "blade"
    );
    
    // Ground vehicle VHF patterns
    vhf_patterns["ground_vehicle"][150.0] = AntennaPatternInfo(
        "leopard1_tank_vhf",
        "antenna_patterns/ground_vehicles/leopard1_tank/leopard1_tank_vhf.ez",
        150.0, "ground_vehicle", "whip"
    );
    
    vhf_patterns["ground_vehicle"][150.0] = AntennaPatternInfo(
        "soviet_uaz_vhf",
        "antenna_patterns/ground_vehicles/soviet_uaz/soviet_uaz_vhf.ez",
        150.0, "ground_vehicle", "whip"
    );
    
    // Ground-based VHF patterns (10m height)
    vhf_patterns["ground_station"][144.5] = AntennaPatternInfo(
        "yagi_144mhz",
        "antenna_patterns/Ground-based/yagi_144mhz/yagi_144mhz_11element.ez",
        144.5, "ground_station", "yagi"
    );
    
    // Ground-based UHF patterns (10m height)
    uhf_patterns["ground_station"][432.0] = AntennaPatternInfo(
        "yagi_70cm",
        "antenna_patterns/Ground-based/yagi_70cm/yagi_70cm_16element.ez",
        432.0, "ground_station", "yagi"
    );
    
    // Dual-band omnidirectional patterns (10m height)
    vhf_patterns["ground_station"][145.0] = AntennaPatternInfo(
        "dual_band_omni_vhf",
        "antenna_patterns/Ground-based/dual_band_omni/dual_band_omni_2m_70cm.ez",
        145.0, "ground_station", "omni"
    );
    
    uhf_patterns["ground_station"][432.0] = AntennaPatternInfo(
        "dual_band_omni_uhf",
        "antenna_patterns/Ground-based/dual_band_omni/dual_band_omni_2m_70cm.ez",
        432.0, "ground_station", "omni"
    );
    
    // Maritime VHF patterns (placeholder)
    vhf_patterns["maritime"][150.0] = AntennaPatternInfo(
        "maritime_vhf",
        "antenna_patterns/maritime/maritime_vhf.ez",
        150.0, "maritime", "whip"
    );
}

void FGCom_AntennaPatternMapping::initializeUHFPatterns() {
    // Military UHF patterns
    uhf_patterns["military"][400.0] = AntennaPatternInfo(
        "military_uhf_tactical",
        "antenna_patterns/military/uhf_tactical.ez",
        400.0, "military", "whip"
    );
    
    // Civilian UHF patterns
    uhf_patterns["civilian"][450.0] = AntennaPatternInfo(
        "civilian_uhf",
        "antenna_patterns/civilian/uhf_civilian.ez",
        450.0, "civilian", "whip"
    );
    
    // Default UHF pattern
    uhf_patterns["default"][400.0] = AntennaPatternInfo(
        "default_uhf",
        "antenna_patterns/default/uhf_default.ez",
        400.0, "default", "whip"
    );
}

AntennaPatternInfo FGCom_AntennaPatternMapping::getVHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    auto vehicle_it = vhf_patterns.find(vehicle_type);
    if (vehicle_it == vhf_patterns.end()) {
        // Try to find closest frequency for any vehicle type
        return getClosestVHFPattern(vehicle_type, frequency_mhz);
    }
    
    auto freq_it = vehicle_it->second.find(frequency_mhz);
    if (freq_it != vehicle_it->second.end()) {
        return freq_it->second;
    }
    
    // Find closest frequency
    return getClosestVHFPattern(vehicle_type, frequency_mhz);
}

AntennaPatternInfo FGCom_AntennaPatternMapping::getUHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    auto vehicle_it = uhf_patterns.find(vehicle_type);
    if (vehicle_it == uhf_patterns.end()) {
        // Try to find closest frequency for any vehicle type
        return getClosestUHFPattern(vehicle_type, frequency_mhz);
    }
    
    auto freq_it = vehicle_it->second.find(frequency_mhz);
    if (freq_it != vehicle_it->second.end()) {
        return freq_it->second;
    }
    
    // Find closest frequency
    return getClosestUHFPattern(vehicle_type, frequency_mhz);
}

std::vector<AntennaPatternInfo> FGCom_AntennaPatternMapping::getAvailableVHFPatterns(const std::string& vehicle_type) {
    std::vector<AntennaPatternInfo> patterns;
    
    auto vehicle_it = vhf_patterns.find(vehicle_type);
    if (vehicle_it != vhf_patterns.end()) {
        for (const auto& freq_pair : vehicle_it->second) {
            patterns.push_back(freq_pair.second);
        }
    }
    
    return patterns;
}

std::vector<AntennaPatternInfo> FGCom_AntennaPatternMapping::getAvailableUHFPatterns(const std::string& vehicle_type) {
    std::vector<AntennaPatternInfo> patterns;
    
    auto vehicle_it = uhf_patterns.find(vehicle_type);
    if (vehicle_it != uhf_patterns.end()) {
        for (const auto& freq_pair : vehicle_it->second) {
            patterns.push_back(freq_pair.second);
        }
    }
    
    return patterns;
}

bool FGCom_AntennaPatternMapping::hasVHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    auto vehicle_it = vhf_patterns.find(vehicle_type);
    if (vehicle_it == vhf_patterns.end()) return false;
    
    return vehicle_it->second.find(frequency_mhz) != vehicle_it->second.end();
}

bool FGCom_AntennaPatternMapping::hasUHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    auto vehicle_it = uhf_patterns.find(vehicle_type);
    if (vehicle_it == uhf_patterns.end()) return false;
    
    return vehicle_it->second.find(frequency_mhz) != vehicle_it->second.end();
}

bool FGCom_AntennaPatternMapping::loadPatternFromFile(const std::string& pattern_file, AntennaPatternInfo& info) {
    std::ifstream file(pattern_file);
    if (!file.is_open()) {
        return false;
    }
    
    // Basic file existence check
    info.is_loaded = true;
    return true;
}

AntennaPatternInfo FGCom_AntennaPatternMapping::getClosestVHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    AntennaPatternInfo closest;
    double min_diff = std::numeric_limits<double>::max();
    
    auto vehicle_it = vhf_patterns.find(vehicle_type);
    if (vehicle_it != vhf_patterns.end()) {
        for (const auto& freq_pair : vehicle_it->second) {
            double diff = std::abs(freq_pair.first - frequency_mhz);
            if (diff < min_diff) {
                min_diff = diff;
                closest = freq_pair.second;
            }
        }
    }
    
    return closest;
}

AntennaPatternInfo FGCom_AntennaPatternMapping::getClosestUHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    AntennaPatternInfo closest;
    double min_diff = std::numeric_limits<double>::max();
    
    auto vehicle_it = uhf_patterns.find(vehicle_type);
    if (vehicle_it != uhf_patterns.end()) {
        for (const auto& freq_pair : vehicle_it->second) {
            double diff = std::abs(freq_pair.first - frequency_mhz);
            if (diff < min_diff) {
                min_diff = diff;
                closest = freq_pair.second;
            }
        }
    }
    
    return closest;
}

std::string FGCom_AntennaPatternMapping::detectVehicleType(const std::string& vehicle_name) {
    std::string lower_name = vehicle_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    if (lower_name.find("aircraft") != std::string::npos || 
        lower_name.find("plane") != std::string::npos ||
        lower_name.find("b737") != std::string::npos ||
        lower_name.find("c130") != std::string::npos ||
        lower_name.find("cessna") != std::string::npos ||
        lower_name.find("mi4") != std::string::npos) {
        return "aircraft";
    } else if (lower_name.find("tank") != std::string::npos ||
               lower_name.find("leopard") != std::string::npos ||
               lower_name.find("uaz") != std::string::npos ||
               lower_name.find("vehicle") != std::string::npos) {
        return "ground_vehicle";
    } else if (lower_name.find("station") != std::string::npos ||
               lower_name.find("ground") != std::string::npos ||
               lower_name.find("yagi") != std::string::npos ||
               lower_name.find("beam") != std::string::npos) {
        return "ground_station";
    } else if (lower_name.find("ship") != std::string::npos ||
               lower_name.find("boat") != std::string::npos ||
               lower_name.find("maritime") != std::string::npos) {
        return "maritime";
    } else if (lower_name.find("military") != std::string::npos ||
               lower_name.find("tactical") != std::string::npos) {
        return "military";
    } else if (lower_name.find("civilian") != std::string::npos) {
        return "civilian";
    }
    
    return "default";
}

bool FGCom_AntennaPatternMapping::isVHFFrequency(double frequency_mhz) {
    return frequency_mhz >= 30.0 && frequency_mhz <= 300.0;
}

bool FGCom_AntennaPatternMapping::isUHFFrequency(double frequency_mhz) {
    return frequency_mhz > 300.0;
}

// Convenience functions
AntennaPatternInfo getAntennaPattern(const std::string& vehicle_type, double frequency_mhz) {
    if (!g_antenna_pattern_mapping) {
        g_antenna_pattern_mapping = std::make_unique<FGCom_AntennaPatternMapping>();
    }
    
    if (g_antenna_pattern_mapping->isVHFFrequency(frequency_mhz)) {
        return g_antenna_pattern_mapping->getVHFPattern(vehicle_type, frequency_mhz);
    } else if (g_antenna_pattern_mapping->isUHFFrequency(frequency_mhz)) {
        return g_antenna_pattern_mapping->getUHFPattern(vehicle_type, frequency_mhz);
    }
    
    return AntennaPatternInfo(); // Default empty pattern
}

bool loadAntennaPattern(const std::string& vehicle_type, double frequency_mhz) {
    if (!g_antenna_pattern_mapping) {
        g_antenna_pattern_mapping = std::make_unique<FGCom_AntennaPatternMapping>();
    }
    
    AntennaPatternInfo info = getAntennaPattern(vehicle_type, frequency_mhz);
    if (info.antenna_name.empty()) {
        return false;
    }
    
    return g_antenna_pattern_mapping->loadPatternFromFile(info.pattern_file, info);
}
