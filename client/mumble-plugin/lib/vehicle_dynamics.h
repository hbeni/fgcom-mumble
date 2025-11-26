#ifndef FGCOM_VEHICLE_DYNAMICS_H
#define FGCOM_VEHICLE_DYNAMICS_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <memory>

// Vehicle dynamics data structures
struct fgcom_vehicle_attitude {
    float pitch_deg;        // Pitch angle in degrees (-90 to +90)
    float roll_deg;         // Roll angle in degrees (-180 to +180)
    float yaw_deg;          // Yaw angle in degrees (0 to 360, true heading)
    float magnetic_heading_deg; // Magnetic heading in degrees (0 to 360)
    float magnetic_declination_deg; // Magnetic declination at current location
    std::chrono::system_clock::time_point timestamp;
    
    fgcom_vehicle_attitude() : pitch_deg(0.0f), roll_deg(0.0f), yaw_deg(0.0f), 
                              magnetic_heading_deg(0.0f), magnetic_declination_deg(0.0f) {
        timestamp = std::chrono::system_clock::now();
    }
};

struct fgcom_vehicle_velocity {
    float speed_knots;      // Speed in knots
    float speed_kmh;        // Speed in km/h
    float speed_ms;         // Speed in m/s
    float course_deg;       // Course over ground in degrees (0-360)
    float vertical_speed_fpm; // Vertical speed in feet per minute
    float vertical_speed_ms;  // Vertical speed in m/s
    std::chrono::system_clock::time_point timestamp;
    
    fgcom_vehicle_velocity() : speed_knots(0.0f), speed_kmh(0.0f), speed_ms(0.0f),
                              course_deg(0.0f), vertical_speed_fpm(0.0f), vertical_speed_ms(0.0f) {
        timestamp = std::chrono::system_clock::now();
    }
};

struct fgcom_vehicle_position {
    double latitude;        // Latitude in decimal degrees
    double longitude;       // Longitude in decimal degrees
    float altitude_ft_msl;  // Altitude in feet MSL
    float altitude_ft_agl;  // Altitude in feet AGL
    float ground_elevation_ft; // Ground elevation in feet MSL
    std::string callsign;   // Vehicle callsign
    std::string vehicle_type; // "aircraft", "boat", "ship", "vehicle", "ground_station"
    std::chrono::system_clock::time_point timestamp;
    
    fgcom_vehicle_position() : latitude(0.0), longitude(0.0), altitude_ft_msl(0.0f),
                              altitude_ft_agl(0.0f), ground_elevation_ft(0.0f) {
        timestamp = std::chrono::system_clock::now();
    }
};

struct fgcom_antenna_orientation {
    std::string antenna_id;     // Unique antenna identifier
    std::string antenna_type;   // "yagi", "dipole", "vertical", "loop", "whip"
    float azimuth_deg;          // Azimuth pointing direction (0-360)
    float elevation_deg;        // Elevation angle (-90 to +90)
    bool is_auto_tracking;      // Is auto-tracking enabled?
    float rotation_speed_deg_per_sec; // Rotation speed for motorized antennas
    std::chrono::system_clock::time_point timestamp;
    
    fgcom_antenna_orientation() : azimuth_deg(0.0f), elevation_deg(0.0f),
                                 is_auto_tracking(false),
                                 rotation_speed_deg_per_sec(0.0f) {
        timestamp = std::chrono::system_clock::now();
    }
};

struct fgcom_vehicle_dynamics {
    fgcom_vehicle_position position;
    fgcom_vehicle_attitude attitude;
    fgcom_vehicle_velocity velocity;
    std::vector<fgcom_antenna_orientation> antennas;
    std::string vehicle_id;     // Unique vehicle identifier
    std::string status;         // "active", "inactive", "maintenance"
    std::chrono::system_clock::time_point last_update;
    
    fgcom_vehicle_dynamics() : status("active") {
        last_update = std::chrono::system_clock::now();
    }
};

// API request/response structures
struct VehicleDynamicsRequest {
    std::string vehicle_id;
    bool include_attitude = true;
    bool include_velocity = true;
    bool include_antennas = true;
    bool include_position = true;
};

struct VehicleDynamicsResponse {
    bool success;
    std::string message;
    fgcom_vehicle_dynamics dynamics;
    std::chrono::system_clock::time_point timestamp;
    
    VehicleDynamicsResponse() : success(false) {
        timestamp = std::chrono::system_clock::now();
    }
};

struct AntennaRotationRequest {
    std::string vehicle_id;
    std::string antenna_id;
    float target_azimuth_deg;
    float target_elevation_deg;
    bool immediate = false;     // If false, use rotation speed
    std::string rotation_mode = "absolute"; // "absolute" or "relative"
};

struct AntennaRotationResponse {
    bool success;
    std::string message;
    fgcom_antenna_orientation current_orientation;
    float estimated_arrival_time_sec;
    std::chrono::system_clock::time_point timestamp;
    
    AntennaRotationResponse() : success(false), estimated_arrival_time_sec(0.0f) {
        timestamp = std::chrono::system_clock::now();
    }
};

struct VehicleListResponse {
    bool success;
    std::string message;
    std::vector<std::string> vehicle_ids;
    std::map<std::string, std::string> vehicle_types;
    std::map<std::string, std::string> vehicle_status;
    std::chrono::system_clock::time_point timestamp;
    
    VehicleListResponse() : success(false) {
        timestamp = std::chrono::system_clock::now();
    }
};

// Main vehicle dynamics manager class
class FGCom_VehicleDynamicsManager {
private:
    std::map<std::string, fgcom_vehicle_dynamics> vehicles;
    std::mutex vehicles_mutex;
    std::chrono::system_clock::time_point last_cleanup;
    bool auto_cleanup_enabled;
    int cleanup_interval_seconds;
    
    // Magnetic declination calculation
    float calculateMagneticDeclination(double lat, double lon);
    
    // Coordinate transformations
    void transformAttitudeToAntennaOrientation(const fgcom_vehicle_attitude& attitude,
                                             fgcom_antenna_orientation& antenna);
    
    // Utility functions
    float normalizeAngle(float angle_deg);
    float calculateDistance(double lat1, double lon1, double lat2, double lon2);
    float calculateBearing(double lat1, double lon1, double lat2, double lon2);
    
public:
    FGCom_VehicleDynamicsManager();
    ~FGCom_VehicleDynamicsManager();
    
    // Vehicle management
    bool registerVehicle(const std::string& vehicle_id, const std::string& vehicle_type);
    bool unregisterVehicle(const std::string& vehicle_id);
    bool updateVehiclePosition(const std::string& vehicle_id, const fgcom_vehicle_position& position);
    bool updateVehicleAttitude(const std::string& vehicle_id, const fgcom_vehicle_attitude& attitude);
    bool updateVehicleVelocity(const std::string& vehicle_id, const fgcom_vehicle_velocity& velocity);
    bool updateVehicleDynamics(const std::string& vehicle_id, const fgcom_vehicle_dynamics& dynamics);
    
    // Antenna management
    bool addAntenna(const std::string& vehicle_id, const fgcom_antenna_orientation& antenna);
    bool removeAntenna(const std::string& vehicle_id, const std::string& antenna_id);
    bool updateAntennaOrientation(const std::string& vehicle_id, const std::string& antenna_id,
                                 const fgcom_antenna_orientation& orientation);
    bool rotateAntenna(const std::string& vehicle_id, const std::string& antenna_id,
                      float target_azimuth, float target_elevation, bool immediate = false);
    
    // Query functions
    VehicleDynamicsResponse getVehicleDynamics(const std::string& vehicle_id);
    VehicleListResponse getAllVehicles();
    std::vector<fgcom_antenna_orientation> getVehicleAntennas(const std::string& vehicle_id);
    fgcom_vehicle_position getVehiclePosition(const std::string& vehicle_id);
    fgcom_vehicle_attitude getVehicleAttitude(const std::string& vehicle_id);
    fgcom_vehicle_velocity getVehicleVelocity(const std::string& vehicle_id);
    
    // Advanced functions
    AntennaRotationResponse calculateAntennaRotation(const AntennaRotationRequest& request);
    std::vector<std::string> getVehiclesInRange(double center_lat, double center_lon, float radius_km);
    std::vector<std::string> getVehiclesByType(const std::string& vehicle_type);
    
    // Auto-tracking functions
    bool enableAutoTracking(const std::string& vehicle_id, const std::string& antenna_id,
                           const std::string& target_vehicle_id);
    bool disableAutoTracking(const std::string& vehicle_id, const std::string& antenna_id);
    bool updateAutoTracking();
    
    // Maintenance functions
    void cleanupInactiveVehicles();
    void setAutoCleanup(bool enabled, int interval_seconds = 300);
    std::map<std::string, std::string> getSystemStatus();
    
    // Configuration
    void setDefaultRotationSpeed(float deg_per_sec);
    void setMagneticDeclinationSource(const std::string& source); // "auto", "manual", "file"
    void setManualMagneticDeclination(float declination_deg);
    
    // Advanced modulation support
    void setVehicleModulationMode(const std::string& vehicle_id, const std::string& mode);
    std::string getVehicleModulationMode(const std::string& vehicle_id);
    bool validateModulationMode(const std::string& mode);
    std::vector<std::string> getSupportedModulationModes();
};

// Global instance
extern std::unique_ptr<FGCom_VehicleDynamicsManager> g_vehicle_dynamics_manager;

// Initialization function
bool initializeVehicleDynamicsManager();
void shutdownVehicleDynamicsManager();

#endif // FGCOM_VEHICLE_DYNAMICS_H
