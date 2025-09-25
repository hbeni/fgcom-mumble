#include "pattern_interpolation.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <iostream>
#include <iomanip>
#include <climits>

// Global pattern interpolation instance
std::unique_ptr<FGCom_PatternInterpolation> g_pattern_interpolation = nullptr;

// Critical altitude ranges for aircraft
const std::vector<int> FGCom_PatternInterpolation::GROUND_EFFECT_ALTITUDES = {
    0, 50, 100, 150, 200, 300, 400, 500, 600, 700, 800, 900, 1000
};

const std::vector<int> FGCom_PatternInterpolation::LOW_ALTITUDE_ALTITUDES = {
    1000, 1200, 1500, 1800, 2100, 2400, 2700, 3000
};

const std::vector<int> FGCom_PatternInterpolation::MEDIUM_ALTITUDE_ALTITUDES = {
    3000, 4000, 5000, 6000, 7000, 8000
};

const std::vector<int> FGCom_PatternInterpolation::HIGH_ALTITUDE_ALTITUDES = {
    8000, 10000, 12000, 15000
};

// Attitude angle intervals for interpolation
const std::vector<int> FGCom_PatternInterpolation::ROLL_ANGLES = {
    -180, -150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150, 180
};

const std::vector<int> FGCom_PatternInterpolation::PITCH_ANGLES = {
    -180, -150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150, 180
};

FGCom_PatternInterpolation::FGCom_PatternInterpolation() {
    // Initialize pattern interpolation system
}

FGCom_PatternInterpolation::~FGCom_PatternInterpolation() {
    // Cleanup
}

bool FGCom_PatternInterpolation::load4NEC2Pattern(const std::string& filename, 
                                                  const std::string& antenna_name,
                                                  int altitude_m, double frequency_mhz) {
    FGCom_AltitudePattern pattern(altitude_m, frequency_mhz);
    
    if (!parse4NEC2File(filename, pattern)) {
        std::cerr << "Failed to parse 4NEC2 file: " << filename << std::endl;
        return false;
    }
    
    if (!validatePattern(pattern)) {
        std::cerr << "Invalid pattern data in file: " << filename << std::endl;
        return false;
    }
    
    // Store pattern in antenna map
    antenna_patterns[antenna_name][altitude_m] = pattern;
    
    std::cout << "Loaded pattern for " << antenna_name 
              << " at " << altitude_m << "m, " << frequency_mhz << "MHz" 
              << " (" << pattern.patterns.size() << " points)" << std::endl;
    
    return true;
}

bool FGCom_PatternInterpolation::load3DAttitudePattern(const std::string& filename, 
                                                       const std::string& antenna_name,
                                                       int roll_deg, int pitch_deg, 
                                                       int altitude_m, double frequency_mhz) {
    FGCom_AttitudePattern pattern(roll_deg, pitch_deg, altitude_m, frequency_mhz);
    
    // Convert FGCom_AttitudePattern to FGCom_AltitudePattern for parsing
    FGCom_AltitudePattern alt_pattern;
    alt_pattern.altitude_m = pattern.altitude_m;
    alt_pattern.frequency_mhz = pattern.frequency_mhz;
    
    if (!parse4NEC2File(filename, alt_pattern)) {
        std::cerr << "Failed to parse 3D attitude pattern file: " << filename << std::endl;
        return false;
    }
    
    if (!validatePattern(alt_pattern)) {
        std::cerr << "Invalid 3D attitude pattern data in file: " << filename << std::endl;
        return false;
    }
    
    // Copy parsed data to attitude pattern
    pattern.patterns = alt_pattern.patterns;
    
    // Create attitude key for storage
    std::string attitude_key = "roll_" + std::to_string(roll_deg) + "_pitch_" + std::to_string(pitch_deg);
    
    // Store the attitude pattern
    attitude_patterns[antenna_name][attitude_key] = pattern;
    
    std::cout << "Loaded 3D attitude pattern: " << antenna_name 
              << " (roll=" << roll_deg << "°, pitch=" << pitch_deg << "°, alt=" << altitude_m << "m, freq=" << frequency_mhz << "MHz)" << std::endl;
    
    return true;
}

bool FGCom_PatternInterpolation::loadAltitudePatterns(const std::string& antenna_name, 
                                                      const std::string& pattern_dir) {
    // This would scan the pattern directory for altitude-specific files
    // and load them automatically
    std::cout << "Loading altitude patterns for " << antenna_name 
              << " from directory: " << pattern_dir << std::endl;
    
    // Implementation would scan for files matching pattern:
    // antenna_name_*m_*MHz.out
    
    return true;
}

double FGCom_PatternInterpolation::getInterpolatedGain(const std::string& antenna_name, 
                                                       int altitude_m, double frequency_mhz,
                                                       double theta_deg, double phi_deg) {
    // Find closest altitude pattern
    const FGCom_AltitudePattern* pattern = getPatternAtAltitude(antenna_name, altitude_m, frequency_mhz);
    if (!pattern) {
        std::cerr << "No pattern found for " << antenna_name 
                  << " at " << altitude_m << "m, " << frequency_mhz << "MHz" << std::endl;
        return -999.0; // Invalid gain
    }
    
    // Find closest pattern points
    std::vector<FGCom_RadiationPattern*> closest = findClosestPatterns(*pattern, theta_deg, phi_deg, 4);
    
    if (closest.size() < 2) {
        std::cerr << "Insufficient pattern points for interpolation" << std::endl;
        return -999.0;
    }
    
    // Simple linear interpolation (could be improved with bilinear)
    double total_weight = 0.0;
    double weighted_gain = 0.0;
    
    for (auto* p : closest) {
        double distance = sqrt(pow(p->theta - theta_deg, 2) + pow(p->phi - phi_deg, 2));
        double weight = 1.0 / (distance + 0.1); // Avoid division by zero
        weighted_gain += p->gain_dbi * weight;
        total_weight += weight;
    }
    
    return weighted_gain / total_weight;
}

double FGCom_PatternInterpolation::get3DAttitudeGain(const std::string& antenna_name, 
                                                     double theta, double phi,
                                                     int roll_deg, int pitch_deg, 
                                                     int altitude_m, double frequency_mhz) {
    // Find closest attitude pattern
    std::string attitude_key = "roll_" + std::to_string(roll_deg) + "_pitch_" + std::to_string(pitch_deg);
    
    if (attitude_patterns.find(antenna_name) == attitude_patterns.end() ||
        attitude_patterns[antenna_name].find(attitude_key) == attitude_patterns[antenna_name].end()) {
        
        // Fallback to standard pattern interpolation
        std::cerr << "No 3D attitude pattern found for " << antenna_name 
                  << " (roll=" << roll_deg << "°, pitch=" << pitch_deg << "°, alt=" << altitude_m << "m, freq=" << frequency_mhz << "MHz)" << std::endl;
        return getInterpolatedGain(antenna_name, altitude_m, frequency_mhz, theta, phi);
    }
    
    const FGCom_AttitudePattern& pattern = attitude_patterns[antenna_name][attitude_key];
    
    // Find closest pattern points
    // Convert FGCom_AttitudePattern to FGCom_AltitudePattern for findClosestPatterns
    FGCom_AltitudePattern alt_pattern;
    alt_pattern.altitude_m = pattern.altitude_m;
    alt_pattern.frequency_mhz = pattern.frequency_mhz;
    alt_pattern.patterns = pattern.patterns;
    
    std::vector<FGCom_RadiationPattern*> closest = findClosestPatterns(alt_pattern, theta, phi, 4);
    
    if (closest.size() < 2) {
        std::cerr << "Insufficient 3D attitude pattern points for interpolation" << std::endl;
        return -999.0;
    }
    
    // Weighted interpolation
    double total_weight = 0.0;
    double weighted_gain = 0.0;
    
    for (auto* p : closest) {
        double distance = sqrt(pow(p->theta - theta, 2) + pow(p->phi - phi, 2));
        double weight = 1.0 / (distance + 0.1); // Avoid division by zero
        weighted_gain += p->gain_dbi * weight;
        total_weight += weight;
    }
    
    return weighted_gain / total_weight;
}

double FGCom_PatternInterpolation::getBilinearInterpolatedGain(const std::string& antenna_name, 
                                                               int altitude_m, double frequency_mhz,
                                                               double theta_deg, double phi_deg) {
    const FGCom_AltitudePattern* pattern = getPatternAtAltitude(antenna_name, altitude_m, frequency_mhz);
    if (!pattern || pattern->patterns.size() < 4) {
        return getInterpolatedGain(antenna_name, altitude_m, frequency_mhz, theta_deg, phi_deg);
    }
    
    // Find four closest points forming a rectangle
    std::vector<FGCom_RadiationPattern*> closest = findClosestPatterns(*pattern, theta_deg, phi_deg, 4);
    
    if (closest.size() < 4) {
        return getInterpolatedGain(antenna_name, altitude_m, frequency_mhz, theta_deg, phi_deg);
    }
    
    // Sort by theta, then phi to find proper rectangle
    std::sort(closest.begin(), closest.end(), [](const FGCom_RadiationPattern* a, const FGCom_RadiationPattern* b) {
        if (a->theta != b->theta) return a->theta < b->theta;
        return a->phi < b->phi;
    });
    
    // Perform bilinear interpolation
    double x1 = closest[0]->theta, y1 = closest[0]->phi;
    double x2 = closest[3]->theta, y2 = closest[3]->phi;
    double q11 = closest[0]->gain_dbi, q12 = closest[1]->gain_dbi;
    double q21 = closest[2]->gain_dbi, q22 = closest[3]->gain_dbi;
    
    return bilinearInterpolate(x1, y1, x2, y2, theta_deg, phi_deg, q11, q12, q21, q22);
}

const FGCom_AltitudePattern* FGCom_PatternInterpolation::getPatternAtAltitude(
    const std::string& antenna_name, int altitude_m, double frequency_mhz) {
    
    auto antenna_it = antenna_patterns.find(antenna_name);
    if (antenna_it == antenna_patterns.end()) {
        return nullptr;
    }
    
    // Find closest altitude
    int closest_altitude = -1;
    int min_diff = INT_MAX;
    
    for (const auto& alt_pair : antenna_it->second) {
        int diff = abs(alt_pair.first - altitude_m);
        if (diff < min_diff) {
            min_diff = diff;
            closest_altitude = alt_pair.first;
        }
    }
    
    if (closest_altitude == -1) {
        return nullptr;
    }
    
    return &antenna_it->second[closest_altitude];
}

double FGCom_PatternInterpolation::getGroundEffectFactor(int altitude_m, double frequency_mhz) {
    if (altitude_m <= 0) return 1.0; // Full ground effects on ground
    
    // Ground effects diminish with altitude
    double lambda = 300.0 / frequency_mhz; // Wavelength in meters
    double height_wavelengths = altitude_m / lambda;
    
    // Ground effects become negligible above ~10 wavelengths
    if (height_wavelengths > 10.0) return 0.0;
    
    // Exponential decay of ground effects
    return exp(-height_wavelengths / 3.0);
}

double FGCom_PatternInterpolation::getMultipathFactor(int altitude_m, double frequency_mhz, double theta_deg) {
    if (altitude_m <= 0) return 1.0; // Maximum multipath on ground
    
    double lambda = 300.0 / frequency_mhz;
    double path_difference = calculatePathDifference(altitude_m, theta_deg);
    double phase_diff = calculatePhaseDifference(path_difference, frequency_mhz);
    
    // Multipath strength depends on phase relationship
    return abs(cos(phase_diff * M_PI / 180.0));
}

FGCom_PatternInterpolation::AltitudeCharacteristics 
FGCom_PatternInterpolation::getAltitudeCharacteristics(int altitude_m, double frequency_mhz) {
    AltitudeCharacteristics chars;
    
    chars.ground_effect_factor = getGroundEffectFactor(altitude_m, frequency_mhz);
    chars.multipath_factor = getMultipathFactor(altitude_m, frequency_mhz, 0.0); // 0° elevation
    chars.pattern_stability = 1.0 - chars.multipath_factor;
    
    if (altitude_m < 1000) {
        chars.dominant_mode = "ground_wave";
    } else if (altitude_m < 5000) {
        chars.dominant_mode = "mixed";
    } else {
        chars.dominant_mode = "sky_wave";
    }
    
    return chars;
}

bool FGCom_PatternInterpolation::isAntennaLoaded(const std::string& antenna_name) {
    return antenna_patterns.find(antenna_name) != antenna_patterns.end();
}

std::vector<int> FGCom_PatternInterpolation::getAvailableAltitudes(const std::string& antenna_name) {
    std::vector<int> altitudes;
    
    auto antenna_it = antenna_patterns.find(antenna_name);
    if (antenna_it != antenna_patterns.end()) {
        for (const auto& alt_pair : antenna_it->second) {
            altitudes.push_back(alt_pair.first);
        }
        std::sort(altitudes.begin(), altitudes.end());
    }
    
    return altitudes;
}

std::vector<double> FGCom_PatternInterpolation::getAvailableFrequencies(const std::string& antenna_name) {
    std::vector<double> frequencies;
    
    auto antenna_it = antenna_patterns.find(antenna_name);
    if (antenna_it != antenna_patterns.end()) {
        for (const auto& alt_pair : antenna_it->second) {
            frequencies.push_back(alt_pair.second.frequency_mhz);
        }
        std::sort(frequencies.begin(), frequencies.end());
        frequencies.erase(std::unique(frequencies.begin(), frequencies.end()), frequencies.end());
    }
    
    return frequencies;
}

double FGCom_PatternInterpolation::getMaximumGain(const std::string& antenna_name, 
                                                  int altitude_m, double frequency_mhz) {
    const FGCom_AltitudePattern* pattern = getPatternAtAltitude(antenna_name, altitude_m, frequency_mhz);
    if (!pattern) return -999.0;
    
    double max_gain = -999.0;
    for (const auto& p : pattern->patterns) {
        max_gain = std::max(max_gain, p.gain_dbi);
    }
    
    return max_gain;
}

double FGCom_PatternInterpolation::getMinimumGain(const std::string& antenna_name, 
                                                  int altitude_m, double frequency_mhz) {
    const FGCom_AltitudePattern* pattern = getPatternAtAltitude(antenna_name, altitude_m, frequency_mhz);
    if (!pattern) return -999.0;
    
    double min_gain = 999.0;
    for (const auto& p : pattern->patterns) {
        min_gain = std::min(min_gain, p.gain_dbi);
    }
    
    return min_gain;
}

double FGCom_PatternInterpolation::getAverageGain(const std::string& antenna_name, 
                                                  int altitude_m, double frequency_mhz) {
    const FGCom_AltitudePattern* pattern = getPatternAtAltitude(antenna_name, altitude_m, frequency_mhz);
    if (!pattern || pattern->patterns.empty()) return -999.0;
    
    double total_gain = 0.0;
    for (const auto& p : pattern->patterns) {
        total_gain += p.gain_dbi;
    }
    
    return total_gain / pattern->patterns.size();
}

double FGCom_PatternInterpolation::calculateGroundReflectionCoefficient(int altitude_m, 
                                                                        double frequency_mhz,
                                                                        double theta_deg, 
                                                                        double ground_conductivity) {
    // Simplified ground reflection coefficient calculation
    double lambda = 300.0 / frequency_mhz;
    double grazing_angle = 90.0 - theta_deg;
    
    if (grazing_angle <= 0) return 0.0; // No reflection for upward angles
    
    // Fresnel reflection coefficient (simplified)
    double n = sqrt(ground_conductivity / (2 * M_PI * frequency_mhz * 8.854e-12));
    double cos_theta = cos(grazing_angle * M_PI / 180.0);
    
    return (cos_theta - n) / (cos_theta + n);
}

double FGCom_PatternInterpolation::calculatePathDifference(int altitude_m, double theta_deg) {
    // Calculate path difference between direct and reflected rays
    double grazing_angle = 90.0 - theta_deg;
    if (grazing_angle <= 0) return 0.0;
    
    return 2.0 * altitude_m * sin(grazing_angle * M_PI / 180.0);
}

double FGCom_PatternInterpolation::calculatePhaseDifference(double path_diff_m, double frequency_mhz) {
    double lambda = 300.0 / frequency_mhz;
    return (path_diff_m / lambda) * 360.0; // Phase in degrees
}

void FGCom_PatternInterpolation::smoothPattern(FGCom_AltitudePattern& pattern, double smoothing_factor) {
    // Simple smoothing algorithm (could be improved with more sophisticated methods)
    if (pattern.patterns.size() < 3) return;
    
    std::vector<double> smoothed_gains(pattern.patterns.size());
    
    for (size_t i = 0; i < pattern.patterns.size(); ++i) {
        double sum = 0.0;
        int count = 0;
        
        // Average with neighboring points
        for (int j = -1; j <= 1; ++j) {
            int idx = i + j;
            if (idx >= 0 && idx < (int)pattern.patterns.size()) {
                sum += pattern.patterns[idx].gain_dbi;
                count++;
            }
        }
        
        smoothed_gains[i] = (1.0 - smoothing_factor) * pattern.patterns[i].gain_dbi + 
                           smoothing_factor * (sum / count);
    }
    
    // Apply smoothed gains
    for (size_t i = 0; i < pattern.patterns.size(); ++i) {
        pattern.patterns[i].gain_dbi = smoothed_gains[i];
    }
}

void FGCom_PatternInterpolation::filterPattern(FGCom_AltitudePattern& pattern, double min_gain_threshold) {
    // Remove points below threshold
    pattern.patterns.erase(
        std::remove_if(pattern.patterns.begin(), pattern.patterns.end(),
                      [min_gain_threshold](const FGCom_RadiationPattern& p) {
                          return p.gain_dbi < min_gain_threshold;
                      }),
        pattern.patterns.end());
}

// Private helper functions
double FGCom_PatternInterpolation::linearInterpolate(double x1, double y1, double x2, double y2, double x) {
    if (x2 == x1) return y1;
    return y1 + (y2 - y1) * (x - x1) / (x2 - x1);
}

double FGCom_PatternInterpolation::bilinearInterpolate(double x1, double y1, double x2, double y2,
                                                       double x, double y, double q11, double q12, 
                                                       double q21, double q22) {
    double denom = (x2 - x1) * (y2 - y1);
    if (denom == 0) return q11;
    
    double f1 = ((x2 - x) * (y2 - y)) / denom;
    double f2 = ((x - x1) * (y2 - y)) / denom;
    double f3 = ((x2 - x) * (y - y1)) / denom;
    double f4 = ((x - x1) * (y - y1)) / denom;
    
    return q11 * f1 + q21 * f2 + q12 * f3 + q22 * f4;
}

std::vector<FGCom_RadiationPattern*> FGCom_PatternInterpolation::findClosestPatterns(
    const FGCom_AltitudePattern& pattern, double theta_deg, double phi_deg, int count) {
    
    std::vector<std::pair<double, FGCom_RadiationPattern*>> distances;
    
    for (auto& p : pattern.patterns) {
        double distance = sqrt(pow(p.theta - theta_deg, 2) + pow(p.phi - phi_deg, 2));
        distances.push_back(std::make_pair(distance, const_cast<FGCom_RadiationPattern*>(&p)));
    }
    
    // Sort by distance
    std::sort(distances.begin(), distances.end());
    
    // Return closest points
    std::vector<FGCom_RadiationPattern*> result;
    for (int i = 0; i < std::min(count, (int)distances.size()); ++i) {
        result.push_back(distances[i].second);
    }
    
    return result;
}

bool FGCom_PatternInterpolation::parse4NEC2File(const std::string& filename, FGCom_AltitudePattern& pattern) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Cannot open 4NEC2 file: " << filename << std::endl;
        return false;
    }
    
    std::string line;
    bool in_pattern_section = false;
    
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        
        // Look for pattern data section
        if (line.find("RADIATION PATTERN") != std::string::npos ||
            line.find("FAR FIELD") != std::string::npos) {
            in_pattern_section = true;
            continue;
        }
        
        if (in_pattern_section) {
            // Parse pattern data (format varies by 4NEC2 version)
            std::istringstream iss(line);
            double theta, phi, gain, phase;
            std::string pol;
            
            if (iss >> theta >> phi >> gain >> phase >> pol) {
                FGCom_RadiationPattern p(theta, phi, gain, phase, pol);
                pattern.patterns.push_back(p);
            }
        }
    }
    
    file.close();
    
    if (pattern.patterns.empty()) {
        std::cerr << "No pattern data found in file: " << filename << std::endl;
        return false;
    }
    
    return true;
}

bool FGCom_PatternInterpolation::validatePattern(const FGCom_AltitudePattern& pattern) {
    if (pattern.patterns.empty()) return false;
    
    // Check for reasonable gain values
    for (const auto& p : pattern.patterns) {
        if (p.gain_dbi < -100 || p.gain_dbi > 50) return false;
        if (p.theta < -180 || p.theta > 180) return false;
        if (p.phi < 0 || p.phi > 360) return false;
    }
    
    return true;
}

FGCom_PatternInterpolation::PatternStats 
FGCom_PatternInterpolation::calculatePatternStats(const FGCom_AltitudePattern& pattern) {
    PatternStats stats;
    
    if (pattern.patterns.empty()) {
        stats.max_gain = stats.min_gain = stats.avg_gain = stats.std_dev = -999.0;
        stats.total_points = 0;
        return stats;
    }
    
    stats.total_points = pattern.patterns.size();
    stats.max_gain = stats.min_gain = pattern.patterns[0].gain_dbi;
    
    double sum = 0.0;
    for (const auto& p : pattern.patterns) {
        stats.max_gain = std::max(stats.max_gain, p.gain_dbi);
        stats.min_gain = std::min(stats.min_gain, p.gain_dbi);
        sum += p.gain_dbi;
    }
    
    stats.avg_gain = sum / pattern.patterns.size();
    
    // Calculate standard deviation
    double variance = 0.0;
    for (const auto& p : pattern.patterns) {
        variance += pow(p.gain_dbi - stats.avg_gain, 2);
    }
    stats.std_dev = sqrt(variance / pattern.patterns.size());
    
    return stats;
}

// Altitude utility functions
namespace FGCom_AltitudeUtils {
    FGCom_AltitudeUtils::AltitudeCategory getAltitudeCategory(int altitude_m) {
        if (altitude_m <= 1000) return GROUND_EFFECT;
        if (altitude_m <= 3000) return LOW_ALTITUDE;
        if (altitude_m <= 8000) return MEDIUM_ALTITUDE;
        return HIGH_ALTITUDE;
    }
    
    int getRecommendedSamplingInterval(int altitude_m) {
        AltitudeCategory cat = getAltitudeCategory(altitude_m);
        switch (cat) {
            case GROUND_EFFECT: return 50;   // Dense sampling
            case LOW_ALTITUDE: return 200;   // Moderate sampling
            case MEDIUM_ALTITUDE: return 500; // Wider intervals
            case HIGH_ALTITUDE: return 1000;  // Wide intervals
            default: return 500;
        }
    }
    
    bool isCriticalTransitionZone(int altitude_m) {
        return altitude_m >= 0 && altitude_m <= 1000;
    }
    
    double getGroundEffectStrength(int altitude_m, double frequency_mhz) {
        if (altitude_m <= 0) return 1.0;
        
        double lambda = 300.0 / frequency_mhz;
        double height_wavelengths = altitude_m / lambda;
        
        return exp(-height_wavelengths / 3.0);
    }
    
    double calculateMultipathNullDepth(int altitude_m, double frequency_mhz, double theta_deg) {
        if (altitude_m <= 0) return 0.0; // No nulls on ground
        
        double path_diff = 2.0 * altitude_m * sin((90.0 - theta_deg) * M_PI / 180.0);
        double lambda = 300.0 / frequency_mhz;
        double phase_diff = (path_diff / lambda) * 360.0;
        
        return 20.0 * log10(abs(cos(phase_diff * M_PI / 180.0)) + 0.001);
    }
}

bool FGCom_PatternInterpolation::has3DAttitudePattern(const std::string& antenna_name) {
    return attitude_patterns.find(antenna_name) != attitude_patterns.end() && 
           !attitude_patterns[antenna_name].empty();
}
