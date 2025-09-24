#include "antenna_orientation_calculator.h"
#include <cmath>
#include <algorithm>
#include <iostream>

// Global instance
std::unique_ptr<FGCom_AntennaOrientationCalculator> g_antenna_orientation_calculator = nullptr;

// Constants
const double DEG_TO_RAD = M_PI / 180.0;
const double RAD_TO_DEG = 180.0 / M_PI;

FGCom_AntennaOrientationCalculator::FGCom_AntennaOrientationCalculator() {
    // Constructor
}

FGCom_AntennaOrientationCalculator::~FGCom_AntennaOrientationCalculator() {
    // Destructor
}

bool FGCom_AntennaOrientationCalculator::initialize() {
    std::lock_guard<std::mutex> lock(calculator_mutex);
    
    loadAntennaCharacteristics();
    setDefaultAntennaCharacteristics();
    
    return true;
}

void FGCom_AntennaOrientationCalculator::loadAntennaCharacteristics() {
    // Load antenna characteristics from configuration or database
    // For now, we'll set default characteristics
}

void FGCom_AntennaOrientationCalculator::setDefaultAntennaCharacteristics() {
    // Yagi antenna characteristics
    fgcom_antenna_pattern_characteristics yagi_20m;
    yagi_20m.antenna_type = "yagi";
    yagi_20m.beamwidth_azimuth_deg = 65.0f;
    yagi_20m.beamwidth_elevation_deg = 25.0f;
    yagi_20m.front_to_back_ratio_db = 20.0f;
    yagi_20m.side_lobe_level_db = -15.0f;
    yagi_20m.gain_dbi = 7.0f;
    yagi_20m.is_directional = true;
    yagi_20m.frequency_range_mhz = {14.0f, 14.35f};
    antenna_characteristics["yagi_20m"] = yagi_20m;
    
    // Dipole antenna characteristics
    fgcom_antenna_pattern_characteristics dipole;
    dipole.antenna_type = "dipole";
    dipole.beamwidth_azimuth_deg = 360.0f;
    dipole.beamwidth_elevation_deg = 80.0f;
    dipole.front_to_back_ratio_db = 0.0f;
    dipole.side_lobe_level_db = 0.0f;
    dipole.gain_dbi = 2.15f;
    dipole.is_directional = false;
    dipole.frequency_range_mhz = {1.8f, 30.0f};
    antenna_characteristics["dipole"] = dipole;
    
    // Vertical antenna characteristics
    fgcom_antenna_pattern_characteristics vertical;
    vertical.antenna_type = "vertical";
    vertical.beamwidth_azimuth_deg = 360.0f;
    vertical.beamwidth_elevation_deg = 90.0f;
    vertical.front_to_back_ratio_db = 0.0f;
    vertical.side_lobe_level_db = 0.0f;
    vertical.gain_dbi = 0.0f;
    vertical.is_directional = false;
    vertical.frequency_range_mhz = {1.8f, 30.0f};
    antenna_characteristics["vertical"] = vertical;
    
    // Loop antenna characteristics
    fgcom_antenna_pattern_characteristics loop;
    loop.antenna_type = "loop";
    loop.beamwidth_azimuth_deg = 90.0f;
    loop.beamwidth_elevation_deg = 60.0f;
    loop.front_to_back_ratio_db = 15.0f;
    loop.side_lobe_level_db = -10.0f;
    loop.gain_dbi = 3.0f;
    loop.is_directional = true;
    loop.frequency_range_mhz = {1.8f, 30.0f};
    antenna_characteristics["loop"] = loop;
    
    // Whip antenna characteristics
    fgcom_antenna_pattern_characteristics whip;
    whip.antenna_type = "whip";
    whip.beamwidth_azimuth_deg = 360.0f;
    whip.beamwidth_elevation_deg = 90.0f;
    whip.front_to_back_ratio_db = 0.0f;
    whip.side_lobe_level_db = 0.0f;
    whip.gain_dbi = -3.0f;
    whip.is_directional = false;
    whip.frequency_range_mhz = {1.8f, 30.0f};
    antenna_characteristics["whip"] = whip;
}

fgcom_antenna_orientation_result FGCom_AntennaOrientationCalculator::calculateAntennaOrientation(
    const fgcom_vehicle_attitude& vehicle_attitude,
    const fgcom_antenna_orientation& antenna_orientation,
    const std::string& antenna_type) {
    
    fgcom_antenna_orientation_result result;
    
    std::lock_guard<std::mutex> lock(calculator_mutex);
    
    // Determine antenna type
    std::string actual_antenna_type = antenna_type.empty() ? antenna_orientation.antenna_type : antenna_type;
    
    // Calculate based on antenna type
    if (actual_antenna_type == "yagi") {
        result = calculateYagiOrientation(vehicle_attitude, antenna_orientation);
    } else if (actual_antenna_type == "dipole") {
        result = calculateDipoleOrientation(vehicle_attitude, antenna_orientation);
    } else if (actual_antenna_type == "vertical") {
        result = calculateVerticalOrientation(vehicle_attitude, antenna_orientation);
    } else if (actual_antenna_type == "loop") {
        result = calculateLoopOrientation(vehicle_attitude, antenna_orientation);
    } else if (actual_antenna_type == "whip") {
        result = calculateVerticalOrientation(vehicle_attitude, antenna_orientation); // Similar to vertical
    } else {
        // Default calculation for unknown antenna types
        result.effective_azimuth_deg = antenna_orientation.azimuth_deg;
        result.effective_elevation_deg = antenna_orientation.elevation_deg;
        result.gain_adjustment_db = 0.0f;
        result.polarization_angle_deg = 0.0f;
        result.is_optimal_orientation = true;
        result.orientation_quality = "unknown";
    }
    
    return result;
}

std::vector<fgcom_antenna_orientation_result> FGCom_AntennaOrientationCalculator::calculateMultipleAntennaOrientations(
    const fgcom_vehicle_attitude& vehicle_attitude,
    const std::vector<fgcom_antenna_orientation>& antennas) {
    
    std::vector<fgcom_antenna_orientation_result> results;
    
    for (const auto& antenna : antennas) {
        results.push_back(calculateAntennaOrientation(vehicle_attitude, antenna));
    }
    
    return results;
}

fgcom_antenna_orientation_result FGCom_AntennaOrientationCalculator::calculateYagiOrientation(
    const fgcom_vehicle_attitude& vehicle_attitude,
    const fgcom_antenna_orientation& antenna_orientation) {
    
    fgcom_antenna_orientation_result result;
    
    // Get Yagi characteristics
    auto it = antenna_characteristics.find("yagi_20m");
    if (it == antenna_characteristics.end()) {
        // Fallback to default Yagi characteristics
        fgcom_antenna_pattern_characteristics default_yagi;
        default_yagi.beamwidth_azimuth_deg = 65.0f;
        default_yagi.beamwidth_elevation_deg = 25.0f;
        default_yagi.gain_dbi = 7.0f;
        result = calculateYagiOrientationEffect(default_yagi, 0.0f, 0.0f);
    } else {
        // Calculate orientation effects
        float azimuth_offset = vehicle_attitude.yaw_deg;
        float elevation_offset = vehicle_attitude.pitch_deg;
        
        result = calculateYagiOrientationEffect(it->second, azimuth_offset, elevation_offset);
    }
    
    // Transform coordinates
    transformVehicleToAntennaCoordinates(vehicle_attitude, antenna_orientation,
                                       result.effective_azimuth_deg, result.effective_elevation_deg);
    
    // Calculate polarization angle
    result.polarization_angle_deg = calculatePolarizationAngle(vehicle_attitude, antenna_orientation);
    
    // Assess quality
    result.orientation_quality = assessOrientationQuality(result.gain_adjustment_db, 
                                                        vehicle_attitude.yaw_deg, 
                                                        vehicle_attitude.pitch_deg);
    
    result.is_optimal_orientation = (result.gain_adjustment_db > -3.0f); // Within 3dB of optimal
    
    return result;
}

fgcom_antenna_orientation_result FGCom_AntennaOrientationCalculator::calculateDipoleOrientation(
    const fgcom_vehicle_attitude& vehicle_attitude,
    const fgcom_antenna_orientation& antenna_orientation) {
    
    fgcom_antenna_orientation_result result;
    
    // Dipoles are less affected by vehicle attitude than directional antennas
    result.effective_azimuth_deg = antenna_orientation.azimuth_deg;
    result.effective_elevation_deg = antenna_orientation.elevation_deg;
    
    // Calculate orientation effect
    result.gain_adjustment_db = calculateDipoleOrientationEffect(vehicle_attitude, antenna_orientation);
    
    // Calculate polarization angle
    result.polarization_angle_deg = calculatePolarizationAngle(vehicle_attitude, antenna_orientation);
    
    // Assess quality
    result.orientation_quality = assessOrientationQuality(result.gain_adjustment_db, 
                                                        vehicle_attitude.yaw_deg, 
                                                        vehicle_attitude.pitch_deg);
    
    result.is_optimal_orientation = (result.gain_adjustment_db > -1.0f); // Dipoles are more tolerant
    
    return result;
}

fgcom_antenna_orientation_result FGCom_AntennaOrientationCalculator::calculateVerticalOrientation(
    const fgcom_vehicle_attitude& vehicle_attitude,
    const fgcom_antenna_orientation& antenna_orientation) {
    
    fgcom_antenna_orientation_result result;
    
    // Vertical antennas are least affected by vehicle attitude
    result.effective_azimuth_deg = antenna_orientation.azimuth_deg;
    result.effective_elevation_deg = antenna_orientation.elevation_deg;
    
    // Calculate orientation effect
    result.gain_adjustment_db = calculateVerticalOrientationEffect(vehicle_attitude);
    
    // Vertical antennas maintain vertical polarization
    result.polarization_angle_deg = 0.0f;
    
    // Assess quality
    result.orientation_quality = assessOrientationQuality(result.gain_adjustment_db, 
                                                        vehicle_attitude.yaw_deg, 
                                                        vehicle_attitude.pitch_deg);
    
    result.is_optimal_orientation = (result.gain_adjustment_db > -0.5f); // Very tolerant
    
    return result;
}

fgcom_antenna_orientation_result FGCom_AntennaOrientationCalculator::calculateLoopOrientation(
    const fgcom_vehicle_attitude& vehicle_attitude,
    const fgcom_antenna_orientation& antenna_orientation) {
    
    fgcom_antenna_orientation_result result;
    
    // Loops cannot be rotated, but vehicle attitude affects their orientation
    result.effective_azimuth_deg = antenna_orientation.azimuth_deg;
    result.effective_elevation_deg = antenna_orientation.elevation_deg;
    
    // Calculate orientation effect
    result.gain_adjustment_db = calculateLoopOrientationEffect(vehicle_attitude, antenna_orientation);
    
    // Calculate polarization angle
    result.polarization_angle_deg = calculatePolarizationAngle(vehicle_attitude, antenna_orientation);
    
    // Assess quality
    result.orientation_quality = assessOrientationQuality(result.gain_adjustment_db, 
                                                        vehicle_attitude.yaw_deg, 
                                                        vehicle_attitude.pitch_deg);
    
    result.is_optimal_orientation = (result.gain_adjustment_db > -2.0f);
    
    return result;
}

fgcom_antenna_orientation FGCom_AntennaOrientationCalculator::calculateOptimalOrientation(
    const fgcom_vehicle_attitude& vehicle_attitude,
    const std::string& antenna_type,
    const std::string& target_direction) {
    
    fgcom_antenna_orientation optimal_orientation;
    optimal_orientation.antenna_type = antenna_type;
    
    // Calculate optimal azimuth based on target direction
    float target_azimuth = 0.0f;
    if (target_direction == "north") {
        target_azimuth = 0.0f;
    } else if (target_direction == "east") {
        target_azimuth = 90.0f;
    } else if (target_direction == "south") {
        target_azimuth = 180.0f;
    } else if (target_direction == "west") {
        target_azimuth = 270.0f;
    } else {
        // Assume it's a bearing in degrees
        try {
            target_azimuth = std::stof(target_direction);
        } catch (...) {
            target_azimuth = 0.0f;
        }
    }
    
    // Compensate for vehicle attitude
    optimal_orientation.azimuth_deg = normalizeAngle(target_azimuth - vehicle_attitude.yaw_deg);
    optimal_orientation.elevation_deg = std::max(-90.0f, std::min(90.0f, -vehicle_attitude.pitch_deg));
    
    return optimal_orientation;
}

bool FGCom_AntennaOrientationCalculator::addAntennaCharacteristics(
    const std::string& antenna_type,
    const fgcom_antenna_pattern_characteristics& characteristics) {
    
    std::lock_guard<std::mutex> lock(calculator_mutex);
    
    antenna_characteristics[antenna_type] = characteristics;
    return true;
}

fgcom_antenna_pattern_characteristics FGCom_AntennaOrientationCalculator::getAntennaCharacteristics(
    const std::string& antenna_type) {
    
    std::lock_guard<std::mutex> lock(calculator_mutex);
    
    auto it = antenna_characteristics.find(antenna_type);
    if (it != antenna_characteristics.end()) {
        return it->second;
    }
    
    // Return default characteristics
    fgcom_antenna_pattern_characteristics default_characteristics;
    default_characteristics.antenna_type = antenna_type;
    return default_characteristics;
}

std::vector<std::string> FGCom_AntennaOrientationCalculator::getAvailableAntennaTypes() {
    std::lock_guard<std::mutex> lock(calculator_mutex);
    
    std::vector<std::string> types;
    for (const auto& pair : antenna_characteristics) {
        types.push_back(pair.first);
    }
    
    return types;
}

float FGCom_AntennaOrientationCalculator::normalizeAngle(float angle_deg) {
    while (angle_deg < 0.0f) angle_deg += 360.0f;
    while (angle_deg >= 360.0f) angle_deg -= 360.0f;
    return angle_deg;
}

float FGCom_AntennaOrientationCalculator::calculateAngleDifference(float angle1_deg, float angle2_deg) {
    float diff = angle1_deg - angle2_deg;
    while (diff > 180.0f) diff -= 360.0f;
    while (diff < -180.0f) diff += 360.0f;
    return std::abs(diff);
}

bool FGCom_AntennaOrientationCalculator::isAntennaTypeSupported(const std::string& antenna_type) {
    std::lock_guard<std::mutex> lock(calculator_mutex);
    
    return antenna_characteristics.find(antenna_type) != antenna_characteristics.end();
}

void FGCom_AntennaOrientationCalculator::setCustomAntennaCharacteristics(
    const std::string& antenna_type,
    float beamwidth_az, float beamwidth_el,
    float gain_dbi, bool is_directional) {
    
    std::lock_guard<std::mutex> lock(calculator_mutex);
    
    fgcom_antenna_pattern_characteristics characteristics;
    characteristics.antenna_type = antenna_type;
    characteristics.beamwidth_azimuth_deg = beamwidth_az;
    characteristics.beamwidth_elevation_deg = beamwidth_el;
    characteristics.gain_dbi = gain_dbi;
    characteristics.is_directional = is_directional;
    
    antenna_characteristics[antenna_type] = characteristics;
}

// Private helper functions
void FGCom_AntennaOrientationCalculator::transformVehicleToAntennaCoordinates(
    const fgcom_vehicle_attitude& vehicle_attitude,
    const fgcom_antenna_orientation& antenna_orientation,
    float& effective_azimuth, float& effective_elevation) {
    
    // Transform vehicle attitude to antenna coordinates
    // This is a simplified transformation - real implementation would use proper rotation matrices
    
    // Azimuth transformation
    effective_azimuth = normalizeAngle(antenna_orientation.azimuth_deg + vehicle_attitude.yaw_deg);
    
    // Elevation transformation
    effective_elevation = std::max(-90.0f, std::min(90.0f, 
                                                   antenna_orientation.elevation_deg + vehicle_attitude.pitch_deg));
}

float FGCom_AntennaOrientationCalculator::calculateGainAdjustment(
    const fgcom_antenna_pattern_characteristics& characteristics,
    float azimuth_offset, float elevation_offset) {
    
    if (!characteristics.is_directional) {
        return 0.0f; // Omnidirectional antennas are not affected
    }
    
    // Calculate gain reduction based on beamwidth
    float azimuth_loss = (azimuth_offset / characteristics.beamwidth_azimuth_deg) * 3.0f; // 3dB per beamwidth
    float elevation_loss = (elevation_offset / characteristics.beamwidth_elevation_deg) * 3.0f;
    
    return -(std::abs(azimuth_loss) + std::abs(elevation_loss));
}

float FGCom_AntennaOrientationCalculator::calculatePolarizationAngle(
    const fgcom_vehicle_attitude& vehicle_attitude,
    const fgcom_antenna_orientation& antenna_orientation) {
    
    // Calculate polarization angle change due to vehicle attitude
    // This is a simplified calculation
    return vehicle_attitude.roll_deg * 0.5f; // Rough approximation
}

std::string FGCom_AntennaOrientationCalculator::assessOrientationQuality(
    float gain_adjustment_db, float azimuth_offset, float elevation_offset) {
    
    if (gain_adjustment_db > -1.0f) {
        return "excellent";
    } else if (gain_adjustment_db > -3.0f) {
        return "good";
    } else if (gain_adjustment_db > -6.0f) {
        return "fair";
    } else {
        return "poor";
    }
}

float FGCom_AntennaOrientationCalculator::calculateYagiOrientationEffect(
    const fgcom_antenna_pattern_characteristics& characteristics,
    float azimuth_offset, float elevation_offset) {
    
    return calculateGainAdjustment(characteristics, azimuth_offset, elevation_offset);
}

float FGCom_AntennaOrientationCalculator::calculateDipoleOrientationEffect(
    const fgcom_vehicle_attitude& vehicle_attitude,
    const fgcom_antenna_orientation& antenna_orientation) {
    
    // Dipoles are affected by vehicle attitude, but less than directional antennas
    float roll_effect = std::abs(vehicle_attitude.roll_deg) * 0.1f; // 0.1dB per degree of roll
    float pitch_effect = std::abs(vehicle_attitude.pitch_deg) * 0.05f; // 0.05dB per degree of pitch
    
    return -(roll_effect + pitch_effect);
}

float FGCom_AntennaOrientationCalculator::calculateVerticalOrientationEffect(
    const fgcom_vehicle_attitude& vehicle_attitude) {
    
    // Vertical antennas are least affected by vehicle attitude
    float roll_effect = std::abs(vehicle_attitude.roll_deg) * 0.02f; // Very small effect
    float pitch_effect = std::abs(vehicle_attitude.pitch_deg) * 0.01f; // Very small effect
    
    return -(roll_effect + pitch_effect);
}

float FGCom_AntennaOrientationCalculator::calculateLoopOrientationEffect(
    const fgcom_vehicle_attitude& vehicle_attitude,
    const fgcom_antenna_orientation& antenna_orientation) {
    
    // Loops are affected by vehicle attitude but cannot be rotated to compensate
    float roll_effect = std::abs(vehicle_attitude.roll_deg) * 0.2f; // Moderate effect
    float pitch_effect = std::abs(vehicle_attitude.pitch_deg) * 0.1f; // Moderate effect
    
    return -(roll_effect + pitch_effect);
}

// Global functions
bool initializeAntennaOrientationCalculator() {
    if (g_antenna_orientation_calculator) {
        return false; // Already initialized
    }
    
    g_antenna_orientation_calculator = std::make_unique<FGCom_AntennaOrientationCalculator>();
    return g_antenna_orientation_calculator->initialize();
}

void shutdownAntennaOrientationCalculator() {
    g_antenna_orientation_calculator.reset();
}
