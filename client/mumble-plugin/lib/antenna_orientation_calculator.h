#ifndef FGCOM_ANTENNA_ORIENTATION_CALCULATOR_H
#define FGCOM_ANTENNA_ORIENTATION_CALCULATOR_H

#include "vehicle_dynamics.h"
#include "radio_model.h"
#include <vector>
#include <map>
#include <memory>

// Antenna orientation calculation results
struct fgcom_antenna_orientation_result {
    float effective_azimuth_deg;    // Effective azimuth after vehicle attitude compensation
    float effective_elevation_deg;  // Effective elevation after vehicle attitude compensation
    float gain_adjustment_db;       // Gain adjustment due to orientation changes
    float polarization_angle_deg;   // Polarization angle change
    bool is_optimal_orientation;    // Is the antenna optimally oriented?
    std::string orientation_quality; // "excellent", "good", "fair", "poor"
    std::chrono::system_clock::time_point timestamp;
    
    fgcom_antenna_orientation_result() : effective_azimuth_deg(0.0f), effective_elevation_deg(0.0f),
                                        gain_adjustment_db(0.0f), polarization_angle_deg(0.0f),
                                        is_optimal_orientation(false), orientation_quality("fair") {
        timestamp = std::chrono::system_clock::now();
    }
};

// Antenna pattern characteristics
struct fgcom_antenna_pattern_characteristics {
    std::string antenna_type;       // "yagi", "dipole", "vertical", "loop", "whip"
    float beamwidth_azimuth_deg;    // 3dB beamwidth in azimuth
    float beamwidth_elevation_deg;  // 3dB beamwidth in elevation
    float front_to_back_ratio_db;   // Front-to-back ratio
    float side_lobe_level_db;       // Side lobe level
    float gain_dbi;                 // Peak gain in dBi
    bool is_directional;            // Is this a directional antenna?
    std::vector<float> frequency_range_mhz; // Operating frequency range
    
    fgcom_antenna_pattern_characteristics() : beamwidth_azimuth_deg(0.0f), beamwidth_elevation_deg(0.0f),
                                             front_to_back_ratio_db(0.0f), side_lobe_level_db(0.0f),
                                             gain_dbi(0.0f), is_directional(false) {}
};

// Main antenna orientation calculator class
class FGCom_AntennaOrientationCalculator {
private:
    std::map<std::string, fgcom_antenna_pattern_characteristics> antenna_characteristics;
    std::mutex calculator_mutex;
    
    // Coordinate transformation functions
    void transformVehicleToAntennaCoordinates(const fgcom_vehicle_attitude& vehicle_attitude,
                                            const fgcom_antenna_orientation& antenna_orientation,
                                            float& effective_azimuth, float& effective_elevation);
    
    // Antenna pattern calculations
    float calculateGainAdjustment(const fgcom_antenna_pattern_characteristics& characteristics,
                                float azimuth_offset, float elevation_offset);
    float calculatePolarizationAngle(const fgcom_vehicle_attitude& vehicle_attitude,
                                   const fgcom_antenna_orientation& antenna_orientation);
    
    // Quality assessment
    std::string assessOrientationQuality(float gain_adjustment_db, float azimuth_offset, float elevation_offset);
    
    // Antenna-specific calculations
    float calculateYagiOrientationEffect(const fgcom_antenna_pattern_characteristics& characteristics,
                                       float azimuth_offset, float elevation_offset);
    float calculateDipoleOrientationEffect(const fgcom_vehicle_attitude& vehicle_attitude,
                                         const fgcom_antenna_orientation& antenna_orientation);
    float calculateVerticalOrientationEffect(const fgcom_vehicle_attitude& vehicle_attitude);
    float calculateLoopOrientationEffect(const fgcom_vehicle_attitude& vehicle_attitude,
                                       const fgcom_antenna_orientation& antenna_orientation);
    
public:
    FGCom_AntennaOrientationCalculator();
    ~FGCom_AntennaOrientationCalculator();
    
    // Initialization
    bool initialize();
    void loadAntennaCharacteristics();
    
    // Main calculation function
    fgcom_antenna_orientation_result calculateAntennaOrientation(
        const fgcom_vehicle_attitude& vehicle_attitude,
        const fgcom_antenna_orientation& antenna_orientation,
        const std::string& antenna_type = "");
    
    // Batch calculations
    std::vector<fgcom_antenna_orientation_result> calculateMultipleAntennaOrientations(
        const fgcom_vehicle_attitude& vehicle_attitude,
        const std::vector<fgcom_antenna_orientation>& antennas);
    
    // Antenna-specific calculations
    fgcom_antenna_orientation_result calculateYagiOrientation(
        const fgcom_vehicle_attitude& vehicle_attitude,
        const fgcom_antenna_orientation& antenna_orientation);
    
    fgcom_antenna_orientation_result calculateDipoleOrientation(
        const fgcom_vehicle_attitude& vehicle_attitude,
        const fgcom_antenna_orientation& antenna_orientation);
    
    fgcom_antenna_orientation_result calculateVerticalOrientation(
        const fgcom_vehicle_attitude& vehicle_attitude,
        const fgcom_antenna_orientation& antenna_orientation);
    
    fgcom_antenna_orientation_result calculateLoopOrientation(
        const fgcom_vehicle_attitude& vehicle_attitude,
        const fgcom_antenna_orientation& antenna_orientation);
    
    // Optimization functions
    fgcom_antenna_orientation calculateOptimalOrientation(
        const fgcom_vehicle_attitude& vehicle_attitude,
        const std::string& antenna_type,
        const std::string& target_direction = ""); // "north", "south", "east", "west", or bearing in degrees
    
    // Antenna characteristics management
    bool addAntennaCharacteristics(const std::string& antenna_type,
                                 const fgcom_antenna_pattern_characteristics& characteristics);
    fgcom_antenna_pattern_characteristics getAntennaCharacteristics(const std::string& antenna_type);
    std::vector<std::string> getAvailableAntennaTypes();
    
    // Utility functions
    float normalizeAngle(float angle_deg);
    float calculateAngleDifference(float angle1_deg, float angle2_deg);
    bool isAntennaTypeSupported(const std::string& antenna_type);
    
    // Configuration
    void setDefaultAntennaCharacteristics();
    void setCustomAntennaCharacteristics(const std::string& antenna_type,
                                       float beamwidth_az, float beamwidth_el,
                                       float gain_dbi, bool is_directional);
};

// Global instance
extern std::unique_ptr<FGCom_AntennaOrientationCalculator> g_antenna_orientation_calculator;

// Initialization function
bool initializeAntennaOrientationCalculator();
void shutdownAntennaOrientationCalculator();

#endif // FGCOM_ANTENNA_ORIENTATION_CALCULATOR_H
