# Game Developer Integration Guide

## Overview

This guide provides comprehensive instructions for game developers and modders who want to integrate FGCom-mumble radio communication simulation into their games. This is a **technical integration guide** requiring significant development expertise.

## Table of Contents

1. [Integration Requirements](#integration-requirements)
2. [Data Exchange Protocol](#data-exchange-protocol)
3. [Game Implementation Requirements](#game-implementation-requirements)
4. [Vehicle Dynamics API](#vehicle-dynamics-api)
5. [FGCom-mumble Data Output](#fgcom-mumble-data-output)
6. [Integration Examples](#integration-examples)
7. [Testing and Validation](#testing-and-validation)
8. [Troubleshooting](#troubleshooting)

## Integration Requirements

### **Technical Prerequisites**

**Development Skills Required:**
- **C++ Programming**: Advanced C++ knowledge for native integration
- **Network Programming**: UDP/TCP socket programming experience
- **Game Engine Knowledge**: Understanding of your game engine's architecture
- **Radio Communication**: Basic understanding of radio frequencies and propagation
- **Server Administration**: Mumble server setup and management

**System Requirements:**
- **Mumble Server**: >= v1.4.0 (Murmur) for communication
- **Network Access**: UDP port 16661 (configurable) for data exchange
- **Memory**: 4GB+ RAM for FGCom-mumble plugin
- **CPU**: Multi-core processor for real-time calculations

### **Integration Complexity Assessment**

**Native Integration (Full Support):**
- **FlightGear**: Complete integration with addon system
- **Development Time**: 2-4 weeks for experienced developers
- **Technical Level**: Advanced

**Manual Integration (External Voice Chat):**
- **Any Game**: Through Mumble voice chat coordination
- **Development Time**: 1-2 weeks for basic integration
- **Technical Level**: Intermediate

**API Integration (Custom Implementation):**
- **Custom Games**: Direct API integration
- **Development Time**: 4-8 weeks for full implementation
- **Technical Level**: Expert

## Data Exchange Protocol

### **UDP Communication Protocol**

FGCom-mumble uses UDP for real-time data exchange between the game and the radio simulation system.

**Default Port**: 16661 (configurable)
**Protocol**: UDP
**Data Format**: Key-value pairs separated by commas
**Encoding**: UTF-8

### **Required Data from Game**

The game must provide the following data to FGCom-mumble:

#### **1. Player Position Data**
```
LAT=latitude, LON=longitude, ALT=altitude_meters
```

**Example:**
```
LAT=40.7128, LON=-74.0060, ALT=100.5
```

#### **2. Radio Configuration Data**
```
COM1_FRQ=frequency_mhz, COM1_PTT=0|1, COM1_PWR=power_watts
COM2_FRQ=frequency_mhz, COM2_PTT=0|1, COM2_PWR=power_watts
```

**Example:**
```
COM1_FRQ=118.500, COM1_PTT=1, COM1_PWR=25.0
COM2_FRQ=121.900, COM2_PTT=0, COM2_PWR=25.0
```

#### **3. Vehicle Information**
```
VEHICLE_TYPE=vehicle_type, VEHICLE_NAME=vehicle_name
```

**Example:**
```
VEHICLE_TYPE=aircraft, VEHICLE_NAME=Cessna_172
```

#### **4. Player Identification**
```
CALLSIGN=player_callsign, PLAYER_ID=unique_id
```

**Example:**
```
CALLSIGN=N123AB, PLAYER_ID=player_001
```

### **Complete UDP Message Format**

```
LAT=40.7128,LON=-74.0060,ALT=100.5,COM1_FRQ=118.500,COM1_PTT=1,COM1_PWR=25.0,COM2_FRQ=121.900,COM2_PTT=0,COM2_PWR=25.0,VEHICLE_TYPE=aircraft,VEHICLE_NAME=Cessna_172,CALLSIGN=N123AB,PLAYER_ID=player_001
```

## Game Implementation Requirements

### **1. Position Tracking System**

**Requirements:**
- Real-time position updates (minimum 10Hz)
- Accurate altitude above sea level
- Coordinate system: WGS84 (GPS coordinates)

**Implementation:**
```cpp
// Example C++ implementation
struct PlayerPosition {
    double latitude;
    double longitude;
    double altitude; // meters above sea level
    double heading;  // degrees (0-360)
    double speed;    // meters per second
};

void UpdatePosition(const PlayerPosition& pos) {
    // Send position data to FGCom-mumble
    SendUDPMessage(pos);
}
```

### **2. Radio System Integration**

**Requirements:**
- Multiple radio channels (minimum 2, recommended 4+)
- Frequency tuning capability
- Push-to-talk (PTT) functionality
- Power level control
- Volume control

**Implementation:**
```cpp
// Example radio system
class RadioSystem {
private:
    struct RadioChannel {
        double frequency;    // MHz
        bool ptt;           // Push-to-talk state
        double power;       // Watts
        double volume;      // 0.0-1.0
        bool enabled;       // Radio on/off
    };
    
    std::vector<RadioChannel> channels;
    
public:
    void SetFrequency(int channel, double freq);
    void SetPTT(int channel, bool pressed);
    void SetPower(int channel, double watts);
    void SetVolume(int channel, double vol);
    void UpdateFGComMumble();
};
```

### **3. Audio System Integration**

**Requirements:**
- Real-time audio processing
- Push-to-talk functionality
- Audio effects (static, interference, distance attenuation)
- Multiple audio channels

**Implementation:**
```cpp
// Example audio integration
class AudioSystem {
private:
    bool ptt_active;
    double audio_level;
    
public:
    void ProcessAudio(float* samples, int count);
    void ApplyRadioEffects(float* samples, int count);
    void SetPTT(bool active);
    void UpdateAudioLevel(double level);
};
```

### **4. Network Communication**

**Requirements:**
- UDP socket communication
- Real-time data transmission
- Error handling and reconnection
- Configurable server settings

**Implementation:**
```cpp
// Example UDP communication
class FGComMumbleClient {
private:
    int udp_socket;
    std::string server_host;
    int server_port;
    
public:
    bool Connect(const std::string& host, int port);
    void SendData(const std::string& data);
    void Disconnect();
    bool IsConnected();
};
```

## Vehicle Dynamics API

The Vehicle Dynamics API provides comprehensive vehicle tracking and antenna management capabilities for games. This API allows games to register vehicles, update their position and attitude, manage antennas, and perform advanced operations like antenna auto-tracking.

### **API Endpoints**

**Base URL**: `http://localhost:8080/api/v1/vehicle-dynamics`

#### **Vehicle Management**
- **POST** `/api/v1/vehicle-dynamics/register` - Register a new vehicle
- **DELETE** `/api/v1/vehicle-dynamics/{vehicle_id}` - Unregister a vehicle
- **GET** `/api/v1/vehicle-dynamics/vehicles` - List all registered vehicles
- **GET** `/api/v1/vehicle-dynamics/{vehicle_id}` - Get vehicle dynamics data

#### **Position and Attitude Updates**
- **PUT** `/api/v1/vehicle-dynamics/{vehicle_id}/position` - Update vehicle position
- **PUT** `/api/v1/vehicle-dynamics/{vehicle_id}/attitude` - Update vehicle attitude
- **PUT** `/api/v1/vehicle-dynamics/{vehicle_id}/velocity` - Update vehicle velocity
- **PUT** `/api/v1/vehicle-dynamics/{vehicle_id}/dynamics` - Update complete dynamics

#### **Antenna Management**
- **POST** `/api/v1/vehicle-dynamics/{vehicle_id}/antennas` - Add antenna to vehicle
- **DELETE** `/api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}` - Remove antenna
- **PUT** `/api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}` - Update antenna orientation
- **GET** `/api/v1/vehicle-dynamics/{vehicle_id}/antennas` - List vehicle antennas

#### **Antenna Rotation and Auto-Tracking**
- **POST** `/api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}/rotate` - Rotate antenna
- **GET** `/api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}/rotation-status` - Get rotation status
- **POST** `/api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}/auto-tracking` - Enable auto-tracking
- **DELETE** `/api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}/auto-tracking` - Disable auto-tracking

### **Data Structures**

#### **Vehicle Registration**
```json
{
  "vehicle_id": "player_001",
  "vehicle_type": "aircraft",
  "vehicle_name": "Cessna_172",
  "initial_position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude": 100.5
  },
  "initial_attitude": {
    "heading": 90.0,
    "pitch": 0.0,
    "roll": 0.0
  }
}
```

#### **Position Update**
```json
{
  "latitude": 40.7128,
  "longitude": -74.0060,
  "altitude": 100.5,
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### **Attitude Update**
```json
{
  "heading": 90.0,
  "pitch": 5.0,
  "roll": -2.0,
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### **Velocity Update**
```json
{
  "ground_speed": 120.5,
  "vertical_speed": 2.0,
  "heading_rate": 1.5,
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### **Antenna Configuration**
```json
{
  "antenna_id": "main_antenna",
  "antenna_type": "yagi",
  "azimuth": 0.0,
  "elevation": 0.0,
  "rotation_speed": 10.0,
  "auto_tracking_enabled": false
}
```

#### **Antenna Rotation Request**
```json
{
  "target_azimuth": 45.0,
  "target_elevation": 10.0,
  "immediate": false,
  "rotation_mode": "absolute"
}
```

### **Game Integration Examples**

#### **1. Vehicle Registration**
```cpp
// Register a new vehicle
class VehicleManager {
private:
    std::string api_base_url = "http://localhost:8080/api/v1/vehicle-dynamics";
    
public:
    bool RegisterVehicle(const std::string& vehicle_id, 
                        const std::string& vehicle_type,
                        const std::string& vehicle_name,
                        double lat, double lon, double alt) {
        
        nlohmann::json request = {
            {"vehicle_id", vehicle_id},
            {"vehicle_type", vehicle_type},
            {"vehicle_name", vehicle_name},
            {"initial_position", {
                {"latitude", lat},
                {"longitude", lon},
                {"altitude", alt}
            }}
        };
        
        return SendAPIRequest("POST", "/register", request);
    }
};
```

#### **2. Position Updates**
```cpp
// Update vehicle position
void UpdateVehiclePosition(const std::string& vehicle_id,
                          double latitude, double longitude, double altitude) {
    nlohmann::json position = {
        {"latitude", latitude},
        {"longitude", longitude},
        {"altitude", altitude},
        {"timestamp", GetCurrentTimestamp()}
    };
    
    SendAPIRequest("PUT", "/" + vehicle_id + "/position", position);
}
```

#### **3. Antenna Management**
```cpp
// Add antenna to vehicle
bool AddAntenna(const std::string& vehicle_id,
                const std::string& antenna_id,
                const std::string& antenna_type,
                float azimuth, float elevation) {
    
    nlohmann::json antenna = {
        {"antenna_id", antenna_id},
        {"antenna_type", antenna_type},
        {"azimuth", azimuth},
        {"elevation", elevation},
        {"rotation_speed", 10.0},
        {"auto_tracking_enabled", false}
    };
    
    return SendAPIRequest("POST", "/" + vehicle_id + "/antennas", antenna);
}
```

#### **4. Multiple Antenna Management for Complex Vehicles**

**Example: Leopard Tank with Multiple Fixed Antennas**

> **Note**: Most military vehicles like the Leopard tank have **fixed antennas** that do not rotate independently. The antenna orientations are relative to the vehicle's heading and change automatically when the vehicle turns. Only vehicles with **mobile radar systems** (like surface-to-air missile systems, radar vehicles, or ground stations) have rotatable antennas. For vehicles with **rotatable antennas**, use the rotation APIs instead.

```cpp
// Complete Leopard Tank integration with multiple antennas
class LeopardTankIntegration {
private:
    std::string vehicle_id = "leopard_tank_001";
    std::string api_base_url = "http://localhost:8080/api/v1/vehicle-dynamics";
    
public:
    // Register Leopard tank with multiple antennas
    bool RegisterLeopardTank() {
        // Register the vehicle
        nlohmann::json vehicle_request = {
            {"vehicle_id", vehicle_id},
            {"vehicle_type", "ground_vehicle"},
            {"vehicle_name", "Leopard_1_Tank"},
            {"initial_position", {
                {"latitude", 40.7128},
                {"longitude", -74.0060},
                {"altitude", 100.0}
            }},
            {"initial_attitude", {
                {"heading", 0.0},
                {"pitch", 0.0},
                {"roll", 0.0}
            }}
        };
        
        auto response = SendAPIRequest("POST", "/register", vehicle_request);
        if (!response["success"]) {
            return false;
        }
        
        // Add main radio antenna (VHF) - Primary communication (fixed)
        AddAntenna("main_vhf_antenna", "whip", 0.0f, 0.0f, 0.0f, false);
        
        // Add secondary radio antenna (UHF) - Tactical communication (fixed)
        AddAntenna("secondary_uhf_antenna", "whip", 0.0f, 0.0f, 0.0f, false);
        
        // Add command antenna (HF) - Long-range communication (fixed)
        AddAntenna("command_hf_antenna", "whip", 0.0f, 0.0f, 0.0f, false);
        
        // Add tactical antenna (VHF) - Squad communication (fixed)
        AddAntenna("tactical_vhf_antenna", "whip", 0.0f, 0.0f, 0.0f, false);
        
        return true;
    }
    
    // Add individual antenna with full configuration
    bool AddAntenna(const std::string& antenna_id,
                   const std::string& antenna_type,
                   float azimuth, float elevation,
                   float rotation_speed, bool auto_tracking) {
        
        nlohmann::json antenna = {
            {"antenna_id", antenna_id},
            {"antenna_type", antenna_type},
            {"azimuth", azimuth},
            {"elevation", elevation},
            {"rotation_speed", rotation_speed},
            {"auto_tracking_enabled", auto_tracking}
        };
        
        auto response = SendAPIRequest("POST", "/" + vehicle_id + "/antennas", antenna);
        return response["success"];
    }
    
    // Update tank position and attitude (affects all antennas)
    bool UpdateTankPosition(double lat, double lon, double alt, 
                           float heading, float pitch, float roll) {
        // Update vehicle position
        nlohmann::json position = {
            {"latitude", lat},
            {"longitude", lon},
            {"altitude", alt},
            {"timestamp", GetCurrentTimestamp()}
        };
        auto pos_response = SendAPIRequest("PUT", "/" + vehicle_id + "/position", position);
        
        // Update vehicle attitude (automatically updates all antenna orientations)
        nlohmann::json attitude = {
            {"heading", heading},
            {"pitch", pitch},
            {"roll", roll},
            {"timestamp", GetCurrentTimestamp()}
        };
        auto att_response = SendAPIRequest("PUT", "/" + vehicle_id + "/attitude", attitude);
        
        return pos_response["success"] && att_response["success"];
    }
    
    // Update antenna orientation (for fixed antennas, this updates the vehicle-relative orientation)
    bool UpdateAntennaOrientation(const std::string& antenna_id,
                                 float azimuth, float elevation) {
        
        nlohmann::json orientation_update = {
            {"antenna_id", antenna_id},
            {"azimuth", azimuth},
            {"elevation", elevation},
            {"timestamp", GetCurrentTimestamp()}
        };
        
        auto response = SendAPIRequest("PUT", 
            "/" + vehicle_id + "/antennas/" + antenna_id, 
            orientation_update);
        return response["success"];
    }
    
    // Get all antennas for the tank (PULL operation)
    std::vector<AntennaInfo> GetAllAntennas() {
        auto response = SendAPIRequest("GET", "/" + vehicle_id + "/antennas", {});
        std::vector<AntennaInfo> antennas;
        
        if (response["success"]) {
            for (const auto& antenna : response["antennas"]) {
                AntennaInfo info;
                info.antenna_id = antenna["antenna_id"];
                info.antenna_type = antenna["antenna_type"];
                info.azimuth = antenna["azimuth"];
                info.elevation = antenna["elevation"];
                info.rotation_speed = antenna["rotation_speed"];
                info.is_auto_tracking = antenna["auto_tracking_enabled"];
                info.timestamp = antenna["timestamp"];
                antennas.push_back(info);
            }
        }
        
        return antennas;
    }
    
    // Get specific antenna status (PULL operation)
    AntennaInfo GetAntennaStatus(const std::string& antenna_id) {
        auto response = SendAPIRequest("GET", 
            "/" + vehicle_id + "/antennas/" + antenna_id, {});
        
        AntennaInfo info;
        if (response["success"]) {
            auto antenna = response["antenna"];
            info.antenna_id = antenna["antenna_id"];
            info.antenna_type = antenna["antenna_type"];
            info.azimuth = antenna["azimuth"];
            info.elevation = antenna["elevation"];
            info.rotation_speed = antenna["rotation_speed"];
            info.is_auto_tracking = antenna["auto_tracking_enabled"];
            info.timestamp = antenna["timestamp"];
        }
        
        return info;
    }
    
    // Update specific antenna (PUSH operation)
    bool UpdateAntenna(const std::string& antenna_id,
                      float azimuth, float elevation,
                      bool auto_tracking = false) {
        
        nlohmann::json antenna_update = {
            {"antenna_id", antenna_id},
            {"azimuth", azimuth},
            {"elevation", elevation},
            {"auto_tracking_enabled", auto_tracking},
            {"timestamp", GetCurrentTimestamp()}
        };
        
        auto response = SendAPIRequest("PUT", 
            "/" + vehicle_id + "/antennas/" + antenna_id, 
            antenna_update);
        return response["success"];
    }
    
    // Remove specific antenna
    bool RemoveAntenna(const std::string& antenna_id) {
        auto response = SendAPIRequest("DELETE", 
            "/" + vehicle_id + "/antennas/" + antenna_id, {});
        return response["success"];
    }
    
    // Enable auto-tracking for specific antenna
    bool EnableAutoTracking(const std::string& antenna_id, 
                           const std::string& target_vehicle_id) {
        nlohmann::json request = {
            {"target_vehicle_id", target_vehicle_id},
            {"tracking_mode", "continuous"}
        };
        
        auto response = SendAPIRequest("POST", 
            "/" + vehicle_id + "/antennas/" + antenna_id + "/auto-tracking", 
            request);
        return response["success"];
    }
    
    // Disable auto-tracking for specific antenna
    bool DisableAutoTracking(const std::string& antenna_id) {
        auto response = SendAPIRequest("DELETE", 
            "/" + vehicle_id + "/antennas/" + antenna_id + "/auto-tracking", {});
        return response["success"];
    }
    
    // Get antenna rotation status
    AntennaRotationStatus GetAntennaRotationStatus(const std::string& antenna_id) {
        auto response = SendAPIRequest("GET", 
            "/" + vehicle_id + "/antennas/" + antenna_id + "/rotation-status", {});
        
        AntennaRotationStatus status;
        if (response["success"]) {
            status.is_rotating = response["is_rotating"];
            status.current_azimuth = response["current_azimuth"];
            status.current_elevation = response["current_elevation"];
            status.target_azimuth = response["target_azimuth"];
            status.target_elevation = response["target_elevation"];
            status.estimated_arrival_time = response["estimated_arrival_time"];
        }
        
        return status;
    }
    
    // Tank-specific operations (fixed antennas - orientation relative to vehicle)
    void SetMainAntennaOrientation(float azimuth, float elevation) {
        UpdateAntennaOrientation("main_vhf_antenna", azimuth, elevation);
    }
    
    void SetSecondaryAntennaOrientation(float azimuth, float elevation) {
        UpdateAntennaOrientation("secondary_uhf_antenna", azimuth, elevation);
    }
    
    void SetCommandAntennaOrientation(float azimuth, float elevation) {
        UpdateAntennaOrientation("command_hf_antenna", azimuth, elevation);
    }
    
    void SetTacticalAntennaOrientation(float azimuth, float elevation) {
        UpdateAntennaOrientation("tactical_vhf_antenna", azimuth, elevation);
    }
    
    // Get complete vehicle dynamics (PULL operation)
    VehicleDynamicsInfo GetVehicleDynamics() {
        auto response = SendAPIRequest("GET", "/" + vehicle_id, {});
        
        VehicleDynamicsInfo dynamics;
        if (response["success"]) {
            auto data = response["dynamics"];
            dynamics.vehicle_id = data["vehicle_id"];
            dynamics.vehicle_type = data["vehicle_type"];
            dynamics.status = data["status"];
            
            // Position
            auto pos = data["position"];
            dynamics.latitude = pos["latitude"];
            dynamics.longitude = pos["longitude"];
            dynamics.altitude = pos["altitude"];
            
            // Attitude
            auto att = data["attitude"];
            dynamics.heading = att["heading"];
            dynamics.pitch = att["pitch"];
            dynamics.roll = att["roll"];
            
            // Antennas
            for (const auto& antenna : data["antennas"]) {
                AntennaInfo info;
                info.antenna_id = antenna["antenna_id"];
                info.antenna_type = antenna["antenna_type"];
                info.azimuth = antenna["azimuth"];
                info.elevation = antenna["elevation"];
                info.rotation_speed = antenna["rotation_speed"];
                info.is_auto_tracking = antenna["auto_tracking_enabled"];
                dynamics.antennas.push_back(info);
            }
        }
        
        return dynamics;
    }
    
    // Update complete vehicle dynamics (PUSH operation)
    bool UpdateVehicleDynamics(const VehicleDynamicsInfo& dynamics) {
        nlohmann::json request = {
            {"vehicle_id", dynamics.vehicle_id},
            {"vehicle_type", dynamics.vehicle_type},
            {"status", dynamics.status},
            {"position", {
                {"latitude", dynamics.latitude},
                {"longitude", dynamics.longitude},
                {"altitude", dynamics.altitude}
            }},
            {"attitude", {
                {"heading", dynamics.heading},
                {"pitch", dynamics.pitch},
                {"roll", dynamics.roll}
            }},
            {"antennas", nlohmann::json::array()}
        };
        
        // Add all antennas
        for (const auto& antenna : dynamics.antennas) {
            nlohmann::json antenna_json = {
                {"antenna_id", antenna.antenna_id},
                {"antenna_type", antenna.antenna_type},
                {"azimuth", antenna.azimuth},
                {"elevation", antenna.elevation},
                {"rotation_speed", antenna.rotation_speed},
                {"auto_tracking_enabled", antenna.is_auto_tracking}
            };
            request["antennas"].push_back(antenna_json);
        }
        
        auto response = SendAPIRequest("PUT", "/" + vehicle_id + "/dynamics", request);
        return response["success"];
    }
};

// Supporting data structures
struct AntennaInfo {
    std::string antenna_id;
    std::string antenna_type;
    float azimuth;
    float elevation;
    float rotation_speed;
    bool is_auto_tracking;
    std::string timestamp;
};

struct AntennaRotationStatus {
    bool is_rotating;
    float current_azimuth;
    float current_elevation;
    float target_azimuth;
    float target_elevation;
    float estimated_arrival_time;
};

struct VehicleDynamicsInfo {
    std::string vehicle_id;
    std::string vehicle_type;
    std::string status;
    double latitude;
    double longitude;
    double altitude;
    float heading;
    float pitch;
    float roll;
    std::vector<AntennaInfo> antennas;
};
```

#### **5. Example: Surface-to-Air Missile System with Rotatable Antennas**

```cpp
// Surface-to-Air Missile (SAM) system with rotatable radar antennas
class SAMSystemIntegration {
private:
    std::string vehicle_id = "sam_system_001";
    std::string api_base_url = "http://localhost:8080/api/v1/vehicle-dynamics";
    
public:
    // Register SAM system with rotatable radar antennas
    bool RegisterSAMSystem() {
        // Register the vehicle
        nlohmann::json vehicle_request = {
            {"vehicle_id", vehicle_id},
            {"vehicle_type", "ground_vehicle"},
            {"vehicle_name", "Patriot_SAM_System"},
            {"initial_position", {
                {"latitude", 40.7128},
                {"longitude", -74.0060},
                {"altitude", 100.0}
            }},
            {"initial_attitude", {
                {"heading", 0.0},
                {"pitch", 0.0},
                {"roll", 0.0}
            }}
        };
        
        auto response = SendAPIRequest("POST", "/register", vehicle_request);
        if (!response["success"]) {
            return false;
        }
        
        // Add search radar antenna (rotatable)
        AddAntenna("search_radar", "yagi", 0.0f, 0.0f, 30.0f, false);
        
        // Add tracking radar antenna (rotatable)
        AddAntenna("tracking_radar", "yagi", 0.0f, 0.0f, 45.0f, false);
        
        // Add communication antenna (fixed)
        AddAntenna("comm_antenna", "whip", 0.0f, 0.0f, 0.0f, false);
        
        return true;
    }
    
    // Rotate search radar to scan area
    bool RotateSearchRadar(float target_azimuth, float target_elevation) {
        nlohmann::json rotation_request = {
            {"target_azimuth", target_azimuth},
            {"target_elevation", target_elevation},
            {"immediate", false},
            {"rotation_mode", "absolute"}
        };
        
        auto response = SendAPIRequest("POST", 
            "/" + vehicle_id + "/antennas/search_radar/rotate", 
            rotation_request);
        return response["success"];
    }
    
    // Rotate tracking radar to follow target
    bool RotateTrackingRadar(float target_azimuth, float target_elevation) {
        nlohmann::json rotation_request = {
            {"target_azimuth", target_azimuth},
            {"target_elevation", target_elevation},
            {"immediate", false},
            {"rotation_mode", "absolute"}
        };
        
        auto response = SendAPIRequest("POST", 
            "/" + vehicle_id + "/antennas/tracking_radar/rotate", 
            rotation_request);
        return response["success"];
    }
    
    // Enable auto-tracking on tracking radar
    bool EnableTargetTracking(const std::string& target_vehicle_id) {
        nlohmann::json request = {
            {"target_vehicle_id", target_vehicle_id},
            {"tracking_mode", "continuous"}
        };
        
        auto response = SendAPIRequest("POST", 
            "/" + vehicle_id + "/antennas/tracking_radar/auto-tracking", 
            request);
        return response["success"];
    }
    
    // Get radar rotation status
    AntennaRotationStatus GetRadarStatus(const std::string& radar_type) {
        auto response = SendAPIRequest("GET", 
            "/" + vehicle_id + "/antennas/" + radar_type + "/rotation-status", {});
        
        AntennaRotationStatus status;
        if (response["success"]) {
            status.is_rotating = response["is_rotating"];
            status.current_azimuth = response["current_azimuth"];
            status.current_elevation = response["current_elevation"];
            status.target_azimuth = response["target_azimuth"];
            status.target_elevation = response["target_elevation"];
            status.estimated_arrival_time = response["estimated_arrival_time"];
        }
        
        return status;
    }
    
    // SAM system operations
    void ScanArea(float start_azimuth, float end_azimuth, float elevation) {
        RotateSearchRadar(start_azimuth, elevation);
        // In real implementation, would sweep from start_azimuth to end_azimuth
    }
    
    void TrackTarget(float target_azimuth, float target_elevation) {
        RotateTrackingRadar(target_azimuth, target_elevation);
    }
    
    void EnableAutoTrack(const std::string& target_id) {
        EnableTargetTracking(target_id);
    }
};
```

#### **6. Usage Example for SAM System**

```cpp
// Game integration example for SAM system
void GameSAMSystemExample() {
    SAMSystemIntegration sam;
    
    // Register SAM system with rotatable radar antennas
    if (!sam.RegisterSAMSystem()) {
        std::cerr << "Failed to register SAM system" << std::endl;
        return;
    }
    
    // Update SAM system position
    sam.UpdateTankPosition(40.7128, -74.0060, 100.0, 0.0f, 0.0f, 0.0f);
    
    // Scan area for targets
    sam.ScanArea(0.0f, 360.0f, 10.0f);
    
    // Track specific target
    sam.TrackTarget(45.0f, 15.0f);
    
    // Enable auto-tracking on enemy aircraft
    sam.EnableAutoTrack("enemy_aircraft_001");
    
    // Get radar status
    auto search_status = sam.GetRadarStatus("search_radar");
    auto tracking_status = sam.GetRadarStatus("tracking_radar");
    
    std::cout << "Search radar rotating: " << search_status.is_rotating << std::endl;
    std::cout << "Tracking radar rotating: " << tracking_status.is_rotating << std::endl;
}
```

#### **7. Usage Example for Leopard Tank**

```cpp
// Game integration example
void GameLeopardTankExample() {
    LeopardTankIntegration tank;
    
    // Register tank with multiple antennas
    if (!tank.RegisterLeopardTank()) {
        std::cerr << "Failed to register Leopard tank" << std::endl;
        return;
    }
    
    // Update tank position and attitude
    tank.UpdateTankPosition(40.7128, -74.0060, 100.0, 45.0f, 0.0f, 0.0f);
    
    // Set fixed antenna orientations (relative to vehicle)
    tank.SetMainAntennaOrientation(0.0f, 0.0f);      // Forward-facing
    tank.SetSecondaryAntennaOrientation(90.0f, 0.0f); // Right-facing
    tank.SetCommandAntennaOrientation(180.0f, 0.0f);  // Rear-facing
    tank.SetTacticalAntennaOrientation(270.0f, 0.0f); // Left-facing
    
    // Get all antenna statuses (PULL operation)
    auto antennas = tank.GetAllAntennas();
    for (const auto& antenna : antennas) {
        std::cout << "Antenna " << antenna.antenna_id 
                  << " at azimuth " << antenna.azimuth 
                  << " elevation " << antenna.elevation << std::endl;
    }
    
    // Update specific antenna orientation (PUSH operation)
    tank.UpdateAntenna("main_vhf_antenna", 0.0f, 0.0f, false);
    
    // Get complete vehicle dynamics (PULL operation)
    auto dynamics = tank.GetVehicleDynamics();
    std::cout << "Tank " << dynamics.vehicle_id 
              << " has " << dynamics.antennas.size() 
              << " antennas" << std::endl;
}
```

#### **4. Antenna Auto-Tracking**
```cpp
// Enable antenna auto-tracking
bool EnableAutoTracking(const std::string& vehicle_id,
                       const std::string& antenna_id,
                       const std::string& target_vehicle_id) {
    
    nlohmann::json request = {
        {"target_vehicle_id", target_vehicle_id},
        {"tracking_mode", "continuous"}
    };
    
    return SendAPIRequest("POST", 
        "/" + vehicle_id + "/antennas/" + antenna_id + "/auto-tracking", 
        request);
}
```

### **Advanced Features**

#### **1. Multi-Vehicle Tracking**
```cpp
// Get all vehicles in range
std::vector<std::string> GetVehiclesInRange(double center_lat, double center_lon, 
                                           float radius_km) {
    nlohmann::json request = {
        {"center_latitude", center_lat},
        {"center_longitude", center_lon},
        {"radius_km", radius_km}
    };
    
    auto response = SendAPIRequest("GET", "/vehicles/in-range", request);
    return response["vehicle_ids"];
}
```

#### **2. Antenna Rotation with Speed Control**
```cpp
// Rotate antenna with speed control
bool RotateAntenna(const std::string& vehicle_id,
                  const std::string& antenna_id,
                  float target_azimuth, float target_elevation,
                  bool immediate = false) {
    
    nlohmann::json request = {
        {"target_azimuth", target_azimuth},
        {"target_elevation", target_elevation},
        {"immediate", immediate},
        {"rotation_mode", "absolute"}
    };
    
    return SendAPIRequest("POST", 
        "/" + vehicle_id + "/antennas/" + antenna_id + "/rotate", 
        request);
}
```

#### **3. Vehicle Status Monitoring**
```cpp
// Get comprehensive vehicle status
VehicleDynamicsResponse GetVehicleStatus(const std::string& vehicle_id) {
    auto response = SendAPIRequest("GET", "/" + vehicle_id, nlohmann::json{});
    
    VehicleDynamicsResponse status;
    status.success = response["success"];
    status.dynamics = ParseVehicleDynamics(response["data"]);
    status.timestamp = ParseTimestamp(response["timestamp"]);
    
    return status;
}
```

### **Performance Considerations**

#### **Update Frequency Guidelines**
- **Position Updates**: 10-20 Hz for aircraft, 5-10 Hz for ground vehicles
- **Attitude Updates**: 10-20 Hz for aircraft, 1-5 Hz for ground vehicles
- **Antenna Updates**: 1-5 Hz for manual control, 10-20 Hz for auto-tracking

#### **Frequency Band Analysis and Update Requirements**

The update frequency requirements vary significantly based on the radio frequency band being simulated. The following analysis provides guidance for optimal simulation fidelity:

**HF (3-30 MHz) - Excellent**
- **Wavelength**: 10-100 meters
- **18m spacing**: Much smaller than wavelength (0.18-1.8 wavelengths)
- **Fresnel zone**: Well resolved at all distances
- **Update frequency**: 1-5 Hz sufficient
- **Effects captured**: Ionospheric propagation, ground wave, sky wave
- **Simulation quality**: More than sufficient for realistic HF communication

**VHF (30-300 MHz) - Good to Excellent**
- **Wavelength**: 1-10 meters
- **18m spacing**: 1.8-18 wavelengths apart
- **First Fresnel zone**: ~100-300m radius
- **Update frequency**: 5-10 Hz recommended
- **Effects captured**: Line-of-sight, tropospheric scatter, ducting
- **Simulation quality**: Adequate for most applications, excellent for ground-based systems

**UHF (300-3000 MHz) - Marginal to Good**
- **Wavelength**: 0.1-1 meters
- **18m spacing**: 18-180 wavelengths apart
- **Update frequency**: 10-20 Hz required
- **Potential issues**: 
  - Missing rapid fading patterns
  - May miss some multipath effects
  - Limited small-scale fading simulation
- **Recommendations**: 
  - Increase update frequency to 20-50 Hz for critical applications
  - Implement additional multipath modeling
  - Use smaller terrain grid spacing

**Microwave (>3 GHz) - Requires High Update Rates**
- **Wavelength**: <0.1 meters
- **Current 18m spacing**: >180 wavelengths apart (inadequate)
- **Target spacing**: 1-3 wavelengths (0.1-0.3m at 3 GHz)
- **Update frequency**: 200-500 Hz required
- **Critical issues**: 
  - Missing fast fading effects
  - Inadequate scattering simulation
  - Limited atmospheric effects modeling
- **Target Update Rate Analysis (3 GHz example)**:
  - **Wavelength**: 0.1 meters (10 cm)
  - **Current spacing**: 18m = 180λ (inadequate)
  - **Target spacing**: 1-3 wavelengths = 0.1-0.3m
  - **Aircraft speed**: 700 knots = 360 m/s
  - **Theoretical ideal**: 360 ÷ 0.2 = 1,800 Hz
  - **Practical simulation**: 200-500 Hz (1.8-0.72m effective spacing)
- **Recommendations**:
  - Use 200-500 Hz update frequencies
  - Implement advanced multipath algorithms
  - Add atmospheric turbulence modeling
  - Use sub-wavelength terrain resolution
  - Consider adaptive update rates based on vehicle speed

#### **Optimized Update Frequencies by Application**

**Aviation Communication (VHF)**
- **Update frequency**: 10-20 Hz
- **Critical for**: Approach/departure, tower communication
- **Effects**: Doppler shift, multipath, atmospheric ducting
  - **Doppler Shift**: Fully implemented with relativistic corrections
  - **Multipath**:  Enhanced implementation with complex scenarios
  - **Atmospheric Ducting**:  Newly implemented with weather integration

**Maritime Communication (HF/VHF)**
- **Update frequency**: 5-10 Hz
- **Critical for**: Long-range HF, coastal VHF
- **Effects**: Ionospheric propagation, sea reflection, atmospheric noise

**Military/Tactical (UHF/Microwave)**
- **Update frequency**: 20-50 Hz
- **Critical for**: Secure communication, data links
- **Effects**: Fast fading, multipath, jamming resistance

**Satellite Communication (Microwave)**
- **Update frequency**: 200-500 Hz
- **Critical for**: Tracking, signal quality
- **Effects**: Atmospheric scintillation, rain fade, tropospheric effects
- **Spacing requirements**: 1-3 wavelengths (0.1-0.3m at 3 GHz)

**General Microwave Propagation (3-10 GHz)**
- **Update frequency**: 300 Hz recommended
- **Spacing**: 1.2m = 12λ at 3 GHz
- **Captures**: Major multipath components
- **Computational load**: Reasonable for most systems
- **Critical for**: Military communications, data links, radar systems

#### **Microwave Frequency Detailed Analysis**

**Target Update Rate Requirements:**
- **Target Update Rate**: 200-500 Hz
- **Reasoning**: At 3 GHz, wavelength = 0.1 meters (10 cm)
- **Current spacing**: 18m = 180λ (inadequate for fast fading)
- **Target spacing**: 1-3 wavelengths = 0.1-0.3m

**Speed-Based Calculations:**
- **Aircraft speed**: 700 knots = 360 m/s
- **For 0.2m spacing**: 360 ÷ 0.2 = 1,800 Hz (theoretical ideal)
- **For practical simulation**: 200-500 Hz (1.8-0.72m effective spacing)

**Specific Recommendations by Application:**

**General Microwave Propagation (3-10 GHz):**
- **Update rate**: 300 Hz
- **Spacing**: 1.2m = 12λ at 3 GHz
- **Captures**: Major multipath components
- **Computational load**: Reasonable for most systems

**High-Speed Applications (Military/Tactical):**
- **Update rate**: 500 Hz
- **Spacing**: 0.72m = 7.2λ at 3 GHz
- **Captures**: Fast fading, rapid multipath changes
- **Computational load**: High, requires optimization

**Satellite/Tracking Applications:**
- **Update rate**: 200-300 Hz
- **Spacing**: 1.2-1.8m = 12-18λ at 3 GHz
- **Captures**: Atmospheric scintillation, orbital dynamics
- **Computational load**: Moderate

#### **API Rate Limiting Configuration**

**CRITICAL**: The default API rate limiting (100 requests/minute) will **block UHF/GHz updates**. The system has been updated with frequency-band-specific rate limits:

**Updated Rate Limits:**
- **General API**: 50,000 requests/minute (833 Hz)
- **UHF (300 MHz+)**: 60,000 requests/minute (1000 Hz)
- **GHz (1 GHz+)**: 120,000 requests/minute (2000 Hz)
- **3 GHz+**: 300,000 requests/minute (5000 Hz)

**Configuration Files Updated:**
- `client/mumble-plugin/lib/fgcom_config.h`: Default rate limit increased to 50,000
- `configs/fgcom-mumble.conf.example`: Updated with new rate limits
- `configs/fgcom-mumble.conf.minimal`: Updated with new rate limits

**For Game Developers:**
- **UHF applications**: Use `checkFrequencyBandRateLimit()` for frequency-aware rate limiting
- **GHz applications**: Automatic higher rate limits for frequencies ≥ 1 GHz
- **3 GHz+ applications**: Maximum rate limit of 300,000 requests/minute

#### **Advanced Radio Propagation Effects**

**Doppler Shift Implementation:**
- **Status**:  Fully implemented
- **Location**: `client/mumble-plugin/lib/frequency_offset.cpp`
- **Features**:
  - Relativistic corrections for high-speed vehicles
  - Atmospheric refraction factor (1.0003)
  - Real-time audio processing integration
  - Configurable parameters for different scenarios
- **Usage**: Automatically applied based on relative velocity and carrier frequency

**Enhanced Multipath Implementation:**
- **Status**:  Fully implemented
- **Location**: `client/mumble-plugin/lib/enhanced_multipath.cpp`
- **Features**:
  - Complex multipath component modeling
  - Ground reflection, building scattering, vegetation effects
  - Vehicle scattering and interference
  - Fading statistics and channel prediction
  - Wideband and fast fading detection
- **Usage**: Integrated into VHF radio model with configurable parameters

**Atmospheric Ducting Implementation:**
- **Status**:  Newly implemented
- **Location**: `client/mumble-plugin/lib/atmospheric_ducting.cpp`
- **Features**:
  - Temperature inversion detection
  - Humidity gradient analysis
  - Wind shear effects
  - Ducting height and thickness calculation
  - Weather data integration
  - Signal enhancement calculation
- **Usage**: Automatically analyzes atmospheric conditions and applies ducting effects

**Integration with Radio Models:**
- **VHF Model**: Enhanced with all three effects
- **UHF Model**: Ready for integration
- **HF Model**: Doppler shift and multipath support
- **Configuration**: Automatic initialization with sensible defaults

#### **Network Optimization**
- Use batch updates when possible
- Implement connection pooling
- Handle network failures gracefully
- Use compression for large data sets
- **Use frequency-band-specific rate limiting for UHF/GHz applications**

#### **Memory Management**
- Cache frequently accessed data
- Implement proper cleanup on vehicle unregistration
- Monitor memory usage for large vehicle counts

### **Error Handling**

#### **Common Error Responses**
```json
{
  "success": false,
  "error_code": "VEHICLE_NOT_FOUND",
  "message": "Vehicle with ID 'player_001' not found",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### **Error Codes**
- `VEHICLE_NOT_FOUND` - Vehicle ID does not exist
- `INVALID_COORDINATES` - Position data is invalid
- `ANTENNA_NOT_FOUND` - Antenna ID does not exist
- `ROTATION_FAILED` - Antenna rotation failed
- `AUTO_TRACKING_FAILED` - Auto-tracking setup failed

## Antenna Pattern Files

### **What Are Antenna Pattern Files?**

Antenna pattern files are essential for realistic radio communication simulation. They contain 3D radiation pattern data that determines how radio signals propagate in different directions from an antenna. These files are crucial for:

- **Realistic Signal Propagation**: Simulating how radio waves travel in different directions
- **Vehicle-Specific Antennas**: Different vehicles have different antenna characteristics
- **3D Attitude Effects**: Antenna performance changes with vehicle pitch, roll, and altitude
- **Frequency-Specific Behavior**: Antennas behave differently at different frequencies

### **Why Antenna Pattern Files Are Needed**

**Without antenna patterns, radio communication would be:**
- **Unrealistic**: All antennas would have identical performance
- **Simplified**: No consideration of antenna directionality
- **Inaccurate**: No simulation of real-world antenna behavior

**With antenna patterns, you get:**
- **Realistic Communication**: Antennas perform differently in different directions
- **Vehicle Authenticity**: Each vehicle type has appropriate antenna characteristics
- **3D Physics**: Antenna performance changes with vehicle attitude
- **Professional Simulation**: Military-grade radio communication simulation

### **How to Add Antenna Patterns to Your Code**

#### **1. Pattern File Structure**

Antenna pattern files are stored in the `lib/antenna_patterns/` directory with this structure:

```
lib/antenna_patterns/
├── Ground-based/
│   ├── 4m_band/
│   │   └── patterns/
│   │       └── 70.15mhz/
│   │           ├── 4m_yagi_0m_roll_0_pitch_0_70.15MHz.txt
│   │           ├── 4m_yagi_0m_roll_0_pitch_45_70.15MHz.txt
│   │           └── 4m_yagi_0m_roll_0_pitch_90_70.15MHz.txt
│   └── Yagi-antennas/
│       └── yagi_144mhz/
│           └── patterns/
│               └── 144.5mhz/
│                   ├── yagi-11element_0m_roll_0_pitch_0_144.5MHz.txt
│                   └── yagi-11element_0m_roll_0_pitch_90_144.5MHz.txt
├── aircraft/
│   ├── Civil/
│   │   └── b737_800/
│   │       └── b737-vhf.ez
│   └── Military/
│       └── c130_hercules/
│           └── c130-military.ez
└── ground_vehicles/
    ├── leopard1_tank/
    │   └── leopard1_tank_vhf.ez
    └── soviet_uaz/
        └── soviet_uaz_vhf.ez
```

#### **2. Pattern File Format**

Each pattern file contains:
- **Header Information**: Frequency, antenna type, altitude
- **Format Description**: Data column descriptions
- **Radiation Data**: Theta, Phi, Gain_dBi, H_Polarization, V_Polarization

**Example Pattern File:**
```
# FGCom-mumble Far-Field Radiation Pattern
# Frequency: 70.15 MHz
# Altitude: 0 m
# Format: Theta Phi Gain_dBi H_Polarization V_Polarization
# Theta: Elevation angle (0-180 degrees)
# Phi: Azimuth angle (0-360 degrees)
# Gain: Antenna gain in dBi
# H_Polarization: Horizontal polarization component
# V_Polarization: Vertical polarization component
0.00 0.00 -6.34 0.0 1.0
5.00 0.00 -6.48 0.0 1.0
10.00 0.00 -7.28 0.0 1.0
...
```

#### **3. Code Integration**

**Add to antenna pattern mapping:**
```cpp
// In lib/antenna_pattern_mapping.cpp
void FGCom_AntennaPatternMapping::initializeVHFPatterns() {
    // Add your custom antenna patterns
    vhf_patterns["your_vehicle_type"][70.15] = AntennaPatternInfo(
        "your_antenna_name",
        "antenna_patterns/your_path/your_pattern_file.txt",
        70.15, "your_vehicle_type", "yagi"
    );
}
```

**Load patterns in your game:**
```cpp
// Load antenna pattern for specific vehicle and frequency
auto pattern_info = getAntennaPattern("ground_station", 70.15);
if (!pattern_info.antenna_name.empty()) {
    // Pattern found, use it for radio calculations
    loadAntennaPattern(pattern_info.vehicle_type, pattern_info.frequency_mhz);
}
```

### **How to Make Antenna Pattern Files**

#### **1. Using the Pattern Generation Tool**

**Generate patterns for ground-based antennas:**
```bash
cd scripts/pattern_generation
./antenna-radiation-pattern-generator.sh --folders "Ground-based/your_antenna_folder" --verbose --overwrite
```

**Generate patterns for aircraft:**
```bash
./antenna-radiation-pattern-generator.sh --folders "aircraft/your_aircraft_folder" --verbose --overwrite
```

#### **2. Manual Pattern Creation**

**For portable radios and ground vehicles:**

**Height Intervals:**
- **Portable Radios**: 0.5m, 1.0m, 1.5m, 2.0m, 2.5m, 3.0m
- **Vehicle Mounted**: 1.0m, 2.0m, 3.0m, 5.0m, 10.0m
- **Fixed Installations**: 5.0m, 10.0m, 20.0m, 50.0m

**Pitch and Roll Requirements:**
- **Pitch Angles**: 0°, 15°, 30°, 45°, 60°, 75°, 90°
- **Roll Angles**: 0°, 15°, 30°, 45°, 60°, 75°, 90°
- **Combined Attitude**: All pitch/roll combinations for 3D simulation

**Pattern File Naming Convention:**
```
{antenna_name}_{altitude}m_roll_{roll}_pitch_{pitch}_{frequency}MHz.txt
```

**Examples:**
- `portable_radio_1m_roll_0_pitch_0_70.15MHz.txt`
- `vehicle_antenna_2m_roll_30_pitch_45_144.5MHz.txt`
- `fixed_yagi_10m_roll_0_pitch_0_432.0MHz.txt`

#### **3. Pattern Generation Requirements**

**For Portable Radios:**
- **Maximum Height**: 3 meters above ground
- **Minimum Height**: 50 cm above ground
- **Height Intervals**: 50cm steps (0.5m, 1.0m, 1.5m, 2.0m, 2.5m, 3.0m)
- **Attitude Coverage**: Full pitch and roll variations
- **Use Case**: Handheld radios, portable equipment

**For Vehicle-Mounted Antennas:**
- **Height Range**: 1m to 10m above ground
- **Height Intervals**: 1m steps (1m, 2m, 3m, 4m, 5m, 6m, 7m, 8m, 9m, 10m)
- **Attitude Coverage**: Full pitch and roll variations
- **Use Case**: Military vehicles, ground stations

**For Fixed Installations:**
- **Height Range**: 5m to 50m above ground
- **Height Intervals**: 5m steps (5m, 10m, 15m, 20m, 25m, 30m, 35m, 40m, 45m, 50m)
- **Attitude Coverage**: Limited pitch variations (0°, 15°, 30°, 45°)
- **Use Case**: Base stations, communication towers

#### **4. Pattern File Validation**

**Check pattern file validity:**
```bash
# Test pattern file loading
./test/test_4m_yagi_patterns

# Validate pattern format
./test/test_pattern_loading
```

**Required Pattern File Properties:**
- **File Size**: > 50KB (substantial radiation data)
- **Data Lines**: > 50 lines of radiation data
- **Format**: Theta, Phi, Gain_dBi, H_Polarization, V_Polarization
- **Frequency**: Correct frequency in header
- **Altitude**: Correct altitude in header

### **Integration Examples**

#### **Example 1: Portable Radio Integration**
```cpp
// Load portable radio pattern for 1.5m height
auto pattern_info = getAntennaPattern("portable_radio", 70.15);
if (!pattern_info.antenna_name.empty()) {
    // Use pattern for radio communication calculations
    float signal_strength = calculateSignalStrength(pattern_info, distance, frequency);
}
```

#### **Example 2: Vehicle Antenna Integration**
```cpp
// Load vehicle antenna pattern based on vehicle height
float vehicle_height = getVehicleHeight(); // 2.5m
auto pattern_info = getAntennaPattern("ground_vehicle", 144.5);
if (!pattern_info.antenna_name.empty()) {
    // Apply vehicle attitude effects
    float pitch = getVehiclePitch(); // 15 degrees
    float roll = getVehicleRoll();   // 30 degrees
    float signal_strength = calculateSignalStrength(pattern_info, distance, frequency, pitch, roll);
}
```

#### **Example 3: Fixed Installation Integration**
```cpp
// Load fixed installation pattern
auto pattern_info = getAntennaPattern("ground_station", 432.0);
if (!pattern_info.antenna_name.empty()) {
    // Fixed installation - limited attitude variations
    float signal_strength = calculateSignalStrength(pattern_info, distance, frequency);
}
```

## Encryption and Digital Modulation Simulation

### **What Is Encryption Simulation?**

Encryption simulation is essential for realistic military radio communication. It simulates encrypted digital voice transmission using NATO-standard protocols like STANAG 4197. This provides:

- **Realistic Military Communication**: Simulates encrypted digital voice over HF radio
- **NATO Standard Compliance**: Uses STANAG 4197 QPSK OFDM modulation
- **Secure Communication**: Simulates encrypted voice transmission
- **Professional Simulation**: Military-grade encrypted radio communication

### **Why Encryption Simulation Is Needed**

**Without encryption simulation:**
- **Unrealistic**: All communication would be unencrypted
- **Simplified**: No consideration of digital modulation
- **Inaccurate**: No simulation of encrypted voice protocols

**With encryption simulation:**
- **Realistic Communication**: Simulates encrypted digital voice transmission
- **NATO Compliance**: Uses standard STANAG 4197 protocols
- **Professional Simulation**: Military-grade encrypted communication
- **Digital Modulation**: QPSK OFDM signal processing

### **STANAG 4197 Implementation**

**STANAG 4197** is a NATO Standardization Agreement that defines modulation and coding characteristics for 2400 bps linear predictive encoded digital speech transmitted over HF radio facilities. This signal utilizes QPSK OFDM modulation similar to MIL-STD-188-110A/B Appendix B waveform.

**Key Characteristics:**
- **Frequency Range**: 3 MHz - 30 MHz (HF band)
- **Modulation**: QPSK (Quadrature Phase-Shift Keying)
- **Multiplexing**: OFDM (Orthogonal Frequency-Division Multiplexing)
- **Bandwidth**: 2.3 kHz
- **Data Rate**: 2400 bps
- **Voice Encoding**: Linear predictive encoded digital speech
- **Encryption**: Advanced Narrowband Digital Voice Terminal (ANDVT)

**Reference**: [STANAG 4197 - Signal Identification Wiki](https://www.sigidwiki.com/wiki/STANAG_4197)

### **How to Code Encryption Simulation**

#### **1. QPSK Modulation Implementation**

**QPSK (Quadrature Phase-Shift Keying) converts digital data into analog signals:**

```cpp
class QPSKModulator {
private:
    double carrier_frequency;
    double symbol_rate;
    double phase_offset;
    
public:
    QPSKModulator(double freq, double rate) 
        : carrier_frequency(freq), symbol_rate(rate), phase_offset(0.0) {}
    
    // Convert 2 bits to QPSK symbol
    std::complex<double> modulateSymbol(uint8_t data) {
        // QPSK constellation mapping
        std::complex<double> symbol;
        switch(data & 0x03) {
            case 0x00: symbol = std::complex<double>(1.0, 1.0); break;   // 00
            case 0x01: symbol = std::complex<double>(-1.0, 1.0); break;  // 01
            case 0x02: symbol = std::complex<double>(1.0, -1.0); break;  // 10
            case 0x03: symbol = std::complex<double>(-1.0, -1.0); break; // 11
        }
        return symbol;
    }
    
    // Generate QPSK modulated signal
    std::vector<std::complex<double>> modulate(const std::vector<uint8_t>& data) {
        std::vector<std::complex<double>> output;
        output.reserve(data.size() * 4); // 2 bits per symbol
        
        for (uint8_t byte : data) {
            // Process 4 symbols per byte (2 bits each)
            for (int i = 0; i < 4; i++) {
                uint8_t symbol_data = (byte >> (6 - 2*i)) & 0x03;
                std::complex<double> symbol = modulateSymbol(symbol_data);
                output.push_back(symbol);
            }
        }
        
        return output;
    }
};
```

#### **2. OFDM Implementation**

**OFDM (Orthogonal Frequency-Division Multiplexing) divides data across multiple subcarriers:**

```cpp
class OFDMModulator {
private:
    int num_subcarriers;
    int num_guard_bands;
    double subcarrier_spacing;
    std::vector<std::complex<double>> fft_buffer;
    
public:
    OFDMModulator(int subcarriers, int guard_bands, double spacing)
        : num_subcarriers(subcarriers), num_guard_bands(guard_bands), 
          subcarrier_spacing(spacing), fft_buffer(subcarriers) {}
    
    // Apply OFDM modulation to QPSK symbols
    std::vector<std::complex<double>> modulate(const std::vector<std::complex<double>>& symbols) {
        std::vector<std::complex<double>> output;
        
        // Map symbols to subcarriers
        for (size_t i = 0; i < symbols.size(); i += num_subcarriers - num_guard_bands) {
            // Clear FFT buffer
            std::fill(fft_buffer.begin(), fft_buffer.end(), std::complex<double>(0, 0));
            
            // Map symbols to active subcarriers
            int symbol_idx = 0;
            for (int k = num_guard_bands/2; k < num_subcarriers - num_guard_bands/2; k++) {
                if (i + symbol_idx < symbols.size()) {
                    fft_buffer[k] = symbols[i + symbol_idx];
                    symbol_idx++;
                }
            }
            
            // Apply IFFT to get time domain signal
            std::vector<std::complex<double>> time_domain = applyIFFT(fft_buffer);
            output.insert(output.end(), time_domain.begin(), time_domain.end());
        }
        
        return output;
    }
    
private:
    std::vector<std::complex<double>> applyIFFT(const std::vector<std::complex<double>>& freq_domain) {
        // Implement IFFT (Inverse Fast Fourier Transform)
        // This is a simplified version - use FFTW library for production
        std::vector<std::complex<double>> time_domain(freq_domain.size());
        
        for (size_t n = 0; n < freq_domain.size(); n++) {
            std::complex<double> sum(0, 0);
            for (size_t k = 0; k < freq_domain.size(); k++) {
                double angle = 2.0 * M_PI * k * n / freq_domain.size();
                sum += freq_domain[k] * std::exp(std::complex<double>(0, angle));
            }
            time_domain[n] = sum / std::sqrt(freq_domain.size());
        }
        
        return time_domain;
    }
};
```

#### **3. STANAG 4197 Preamble Generation**

**STANAG 4197 uses a specific preamble structure:**

```cpp
class STANAG4197Preamble {
private:
    std::vector<std::complex<double>> preamble_data;
    
public:
    STANAG4197Preamble() {
        generatePreamble();
    }
    
    void generatePreamble() {
        // STANAG 4197 preamble: 16 tone data header + 39 tone data payload
        preamble_data.clear();
        
        // Generate 16 tone header (similar to 110A/B App. B)
        for (int i = 0; i < 16; i++) {
            // Known preamble pattern for synchronization
            double phase = 2.0 * M_PI * i / 16.0;
            preamble_data.push_back(std::complex<double>(cos(phase), sin(phase)));
        }
        
        // Add 39 tone data payload structure
        for (int i = 0; i < 39; i++) {
            // Data payload structure
            double phase = 2.0 * M_PI * i / 39.0;
            preamble_data.push_back(std::complex<double>(cos(phase), sin(phase)));
        }
    }
    
    const std::vector<std::complex<double>>& getPreamble() const {
        return preamble_data;
    }
};
```

#### **4. Linear Predictive Coding (LPC) Voice Encoding**

**LPC encodes voice into digital data for transmission:**

```cpp
class LPCVoiceEncoder {
private:
    int frame_size;
    int lpc_order;
    std::vector<double> lpc_coefficients;
    
public:
    LPCVoiceEncoder(int frame_size, int order) 
        : frame_size(frame_size), lpc_order(order), lpc_coefficients(order) {}
    
    // Encode voice frame using LPC
    std::vector<uint8_t> encodeFrame(const std::vector<double>& audio_frame) {
        // Calculate LPC coefficients
        calculateLPCCoefficients(audio_frame);
        
        // Encode residual signal
        std::vector<double> residual = calculateResidual(audio_frame);
        
        // Quantize and pack into bytes
        std::vector<uint8_t> encoded_data;
        encoded_data.reserve(lpc_order + frame_size/8);
        
        // Pack LPC coefficients
        for (int i = 0; i < lpc_order; i++) {
            int16_t coeff = static_cast<int16_t>(lpc_coefficients[i] * 32767);
            encoded_data.push_back((coeff >> 8) & 0xFF);
            encoded_data.push_back(coeff & 0xFF);
        }
        
        // Pack residual signal
        for (size_t i = 0; i < residual.size(); i += 8) {
            uint8_t byte = 0;
            for (int j = 0; j < 8 && i + j < residual.size(); j++) {
                if (residual[i + j] > 0) {
                    byte |= (1 << (7 - j));
                }
            }
            encoded_data.push_back(byte);
        }
        
        return encoded_data;
    }
    
private:
    void calculateLPCCoefficients(const std::vector<double>& frame) {
        // Simplified LPC coefficient calculation
        // Use Levinson-Durbin algorithm for production
        for (int i = 0; i < lpc_order; i++) {
            lpc_coefficients[i] = 0.1 * sin(2.0 * M_PI * i / lpc_order);
        }
    }
    
    std::vector<double> calculateResidual(const std::vector<double>& frame) {
        std::vector<double> residual(frame.size());
        
        // Calculate prediction error
        for (size_t i = lpc_order; i < frame.size(); i++) {
            double prediction = 0.0;
            for (int j = 0; j < lpc_order; j++) {
                prediction += lpc_coefficients[j] * frame[i - j - 1];
            }
            residual[i] = frame[i] - prediction;
        }
        
        return residual;
    }
};
```

#### **5. Complete STANAG 4197 Implementation**

**Integrate all components for complete STANAG 4197 simulation:**

```cpp
class STANAG4197Simulator {
private:
    QPSKModulator qpsk_modulator;
    OFDMModulator ofdm_modulator;
    LPCVoiceEncoder lpc_encoder;
    STANAG4197Preamble preamble_generator;
    
public:
    STANAG4197Simulator() 
        : qpsk_modulator(2400.0, 2400.0),  // 2400 bps
          ofdm_modulator(64, 8, 37.5),     // 64 subcarriers, 8 guard bands, 37.5 Hz spacing
          lpc_encoder(160, 10) {}           // 160 samples, 10th order LPC
    
    // Simulate encrypted voice transmission
    std::vector<std::complex<double>> simulateEncryptedVoice(const std::vector<double>& audio_input) {
        std::vector<std::complex<double>> output;
        
        // Process audio in frames
        for (size_t i = 0; i < audio_input.size(); i += 160) {
            // Extract frame
            std::vector<double> frame(audio_input.begin() + i, 
                                    audio_input.begin() + std::min(i + 160, audio_input.size()));
            
            // Encode voice using LPC
            std::vector<uint8_t> encoded_voice = lpc_encoder.encodeFrame(frame);
            
            // Add preamble for synchronization
            auto preamble = preamble_generator.getPreamble();
            output.insert(output.end(), preamble.begin(), preamble.end());
            
            // Modulate with QPSK
            auto qpsk_symbols = qpsk_modulator.modulate(encoded_voice);
            
            // Apply OFDM modulation
            auto ofdm_signal = ofdm_modulator.modulate(qpsk_symbols);
            output.insert(output.end(), ofdm_signal.begin(), ofdm_signal.end());
        }
        
        return output;
    }
    
    // Generate STANAG 4197 signal characteristics
    void generateSignalCharacteristics() {
        std::cout << "STANAG 4197 Signal Characteristics:" << std::endl;
        std::cout << "  Frequency Range: 3 MHz - 30 MHz" << std::endl;
        std::cout << "  Modulation: QPSK OFDM" << std::endl;
        std::cout << "  Bandwidth: 2.3 kHz" << std::endl;
        std::cout << "  Data Rate: 2400 bps" << std::endl;
        std::cout << "  Voice Encoding: Linear Predictive Coding" << std::endl;
        std::cout << "  Encryption: ANDVT (Advanced Narrowband Digital Voice Terminal)" << std::endl;
    }
};
```

### **Integration with Game Audio System**

#### **Audio Processing Pipeline**

```cpp
class EncryptedVoiceProcessor {
private:
    STANAG4197Simulator stanag_simulator;
    std::vector<double> audio_buffer;
    
public:
    // Process incoming audio for encryption simulation
    std::vector<std::complex<double>> processAudio(const std::vector<double>& input_audio) {
        // Add to buffer
        audio_buffer.insert(audio_buffer.end(), input_audio.begin(), input_audio.end());
        
        // Process when buffer is full
        if (audio_buffer.size() >= 160) { // 160 samples per frame
            auto encrypted_signal = stanag_simulator.simulateEncryptedVoice(audio_buffer);
            audio_buffer.clear();
            return encrypted_signal;
        }
        
        return std::vector<std::complex<double>>();
    }
    
    // Generate encrypted voice sound effects
    void generateEncryptedVoiceSound() {
        // Generate characteristic STANAG 4197 sound
        std::vector<double> audio_samples(48000); // 1 second at 48kHz
        
        for (size_t i = 0; i < audio_samples.size(); i++) {
            // Generate QPSK OFDM characteristic sound
            double time = static_cast<double>(i) / 48000.0;
            audio_samples[i] = 0.1 * sin(2.0 * M_PI * 2400.0 * time) * 
                              cos(2.0 * M_PI * 2400.0 * time);
        }
        
        // Apply to game audio system
        applyAudioToGame(audio_samples);
    }
};
```

### **Research Requirements**

**For proper implementation, developers must research:**

1. **QPSK Modulation Theory**: Study quadrature phase-shift keying principles
2. **OFDM Signal Processing**: Research orthogonal frequency-division multiplexing
3. **Linear Predictive Coding**: Study LPC voice compression algorithms
4. **STANAG 4197 Specification**: Review NATO standardization documents
5. **ANDVT Modem Characteristics**: Study Advanced Narrowband Digital Voice Terminal specifications

**Key Research Areas:**
- **Digital Signal Processing**: FFT/IFFT algorithms for OFDM
- **Voice Compression**: LPC coefficient calculation and residual encoding
- **Modulation Theory**: QPSK constellation mapping and demodulation
- **NATO Standards**: STANAG 4197 protocol implementation
- **Encryption Protocols**: ANDVT modem signal characteristics

**Reference Materials:**
- [STANAG 4197 - Signal Identification Wiki](https://www.sigidwiki.com/wiki/STANAG_4197)
- NATO STANAG 4197 specification documents
- MIL-STD-188-110A/B Appendix B waveform documentation
- Linear Predictive Coding research papers
- QPSK OFDM modulation theory papers

## Weather Data API

### **Weather Data Integration**

> **Note**: All Weather Data API endpoints are controlled by feature toggles. See [Feature Toggle API Control](FEATURE_TOGGLE_API_CONTROL.md) for configuration details.

The Weather Data API provides atmospheric condition effects on radio propagation. This system fetches weather data from multiple sources and uses it to simulate realistic atmospheric effects that affect radio communication across different frequency bands.

### **Weather API Endpoints**

**Base URL**: `http://localhost:8080/api/v1/weather-data`

#### **Get Current Weather Conditions**
```http
GET /api/v1/weather-data/current
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "weather_conditions": {
    "temperature_celsius": 20.0,
    "humidity_percent": 50.0,
    "pressure_hpa": 1013.25,
    "wind_speed_ms": 5.0,
    "wind_direction_deg": 180.0,
    "precipitation_mmh": 0.0,
    "dew_point_celsius": 10.0,
    "visibility_km": 10.0,
    "cloud_cover_percent": 30.0,
    "uv_index": 5.0,
    "air_quality_index": 50.0,
    "pollen_count": 25.0,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### **Get Weather Effects by Frequency**
```http
GET /api/v1/weather-data/frequency-effects?frequency_band=VHF&frequency_hz=100000000
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "frequency_effects": {
    "frequency_band": "VHF",
    "frequency_hz": 100000000.0,
    "weather_effects": {
      "temperature_effects_db": 0.5,
      "humidity_effects_db": 1.2,
      "pressure_effects_db": 0.3,
      "precipitation_effects_db": 0.0,
      "wind_effects_db": 0.2,
      "total_effects_db": 2.2
    },
    "propagation_effects": {
      "line_of_sight": 2.2,
      "tropospheric_scatter": 3.5,
      "ducting": 0.8
    },
    "atmospheric_conditions": {
      "refraction_index": 1.0003,
      "ducting_height_m": 1000.0,
      "absorption_coefficient": 0.001
    },
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### **Game Integration Examples**

#### **1. Weather Effects on Radio Communication**
```cpp
// C++ weather integration example
class WeatherRadioEffects {
private:
    std::string api_base_url = "http://localhost:8080/api/v1/weather-data";
    
public:
    // Get weather effects on radio communication
    float getWeatherEffects(float frequency_hz, float distance_km) {
        // Get current weather conditions
        auto weather_response = sendAPIRequest("GET", "/current", {});
        auto weather = weather_response["weather_conditions"];
        
        // Calculate weather effects
        float temperature_effect = calculateTemperatureEffect(frequency_hz, weather["temperature_celsius"]);
        float humidity_effect = calculateHumidityEffect(frequency_hz, weather["humidity_percent"]);
        float pressure_effect = calculatePressureEffect(frequency_hz, weather["pressure_hpa"]);
        float precipitation_effect = calculatePrecipitationEffect(frequency_hz, weather["precipitation_mmh"]);
        
        return temperature_effect + humidity_effect + pressure_effect + precipitation_effect;
    }
    
    // Calculate temperature effects on radio propagation
    float calculateTemperatureEffect(float frequency_hz, float temperature_celsius) {
        if (frequency_hz < 1000000.0f) { // VLF/LF
            return (temperature_celsius - 20.0f) * 0.001f;
        } else if (frequency_hz < 100000000.0f) { // MF/HF
            return (temperature_celsius - 20.0f) * 0.005f;
        } else if (frequency_hz < 1000000000.0f) { // VHF/UHF
            return (temperature_celsius - 20.0f) * 0.01f;
        } else { // SHF/EHF
            return (temperature_celsius - 20.0f) * 0.02f;
        }
    }
    
    // Calculate humidity effects on radio propagation
    float calculateHumidityEffect(float frequency_hz, float humidity_percent) {
        if (frequency_hz < 1000000.0f) { // VLF/LF
            return (humidity_percent - 50.0f) * 0.002f;
        } else if (frequency_hz < 100000000.0f) { // MF/HF
            return (humidity_percent - 50.0f) * 0.01f;
        } else if (frequency_hz < 1000000000.0f) { // VHF/UHF
            return (humidity_percent - 50.0f) * 0.02f;
        } else { // SHF/EHF
            return (humidity_percent - 50.0f) * 0.05f;
        }
    }
    
    // Calculate precipitation effects (rain, drizzle, etc.)
    float calculatePrecipitationEffect(float frequency_hz, float precipitation_mmh) {
        if (precipitation_mmh > 0.0f) {
            // Rain effects on radio propagation
            if (frequency_hz < 1000000.0f) { // VLF/LF
                return precipitation_mmh * 0.001f;
            } else if (frequency_hz < 100000000.0f) { // MF/HF
                return precipitation_mmh * 0.005f;
            } else if (frequency_hz < 1000000000.0f) { // VHF/UHF
                return precipitation_mmh * 0.01f;
            } else { // SHF/EHF
                return precipitation_mmh * 0.02f;
            }
        }
        return 0.0f;
    }
};
```

#### **2. Rain and Drizzle Effects**
```cpp
// Specific weather condition effects
class PrecipitationEffects {
public:
    // Calculate rain effects on radio communication
    float calculateRainEffects(float frequency_hz, float rain_intensity_mmh) {
        float rain_attenuation = 0.0f;
        
        if (rain_intensity_mmh > 0.0f) {
            // Rain attenuation formula
            float frequency_ghz = frequency_hz / 1000000000.0f;
            rain_attenuation = rain_intensity_mmh * (0.032 * pow(frequency_ghz, 0.5) + 0.001 * pow(frequency_ghz, 2.0));
        }
        
        return rain_attenuation;
    }
    
    // Calculate drizzle effects (lighter precipitation)
    float calculateDrizzleEffects(float frequency_hz, float drizzle_intensity_mmh) {
        float drizzle_attenuation = 0.0f;
        
        if (drizzle_intensity_mmh > 0.0f) {
            // Drizzle has less effect than rain
            float frequency_ghz = frequency_hz / 1000000000.0f;
            drizzle_attenuation = drizzle_intensity_mmh * (0.016 * pow(frequency_ghz, 0.5) + 0.0005 * pow(frequency_ghz, 2.0));
        }
        
        return drizzle_attenuation;
    }
    
    // Calculate moisture effects on radio propagation
    float calculateMoistureEffects(float frequency_hz, float humidity_percent, float temperature_celsius) {
        // Calculate atmospheric moisture effects
        float moisture_factor = humidity_percent / 100.0f;
        float temperature_factor = (temperature_celsius - 20.0f) / 20.0f;
        
        float moisture_effect = 0.0f;
        if (frequency_hz > 1000000000.0f) { // SHF/EHF bands
            moisture_effect = moisture_factor * temperature_factor * 0.1f;
        }
        
        return moisture_effect;
    }
};
```

## Solar Data API

### **Solar Data Integration**

The Solar Data API provides real-time NOAA/SWPC solar data for accurate propagation modeling. This system fetches solar activity data from multiple sources and uses it to calculate realistic radio propagation conditions.

### **Solar Data API Endpoints**

**Base URL**: `http://localhost:8080/api/v1/solar-data`

#### **Get Current Solar Data**
```http
GET /api/v1/solar-data/current
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "solar_data": {
    "timestamp": "2024-01-15T10:30:00Z",
    "solar_flux": 150.2,
    "sunspot_number": 45,
    "k_index": 2,
    "a_index": 8,
    "ap_index": 12,
    "solar_wind": {
      "speed": 450.5,
      "density": 5.2,
      "temperature": 100000.0
    },
    "geomagnetic_field": {
      "bx": 2.1,
      "by": -1.5,
      "bz": -3.2,
      "total_strength": 4.8
    },
    "calculated_parameters": {
      "muf": 25.5,
      "luf": 3.2,
      "critical_frequency": 8.5,
      "propagation_quality": 0.85
    },
    "magnetic_field": "quiet",
    "propagation_conditions": "good",
    "data_source": "noaa_swpc",
    "data_valid": true
  }
}
```

#### **Get Solar Data History**
```http
GET /api/v1/solar-data/history?start_date=2024-01-01T00:00:00Z&end_date=2024-01-15T23:59:59Z&data_points=100
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "solar_history": {
    "start_date": "2024-01-01T00:00:00Z",
    "end_date": "2024-01-15T23:59:59Z",
    "data_points": 100,
    "data": [
      {
        "timestamp": "2024-01-01T00:00:00Z",
        "solar_flux": 145.2,
        "sunspot_number": 42,
        "k_index": 1,
        "a_index": 5,
        "propagation_quality": 0.82
      }
    ]
  }
}
```

#### **Submit Solar Data from Game**
```http
POST /api/v1/solar-data/submit
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "solar_flux": 150.2,
  "k_index": 2,
  "a_index": 8,
  "sunspot_number": 45,
  "ap_index": 12,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Solar data submitted successfully",
  "data_id": "solar_20240115_103000",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### **Submit Batch Solar Data**
```http
POST /api/v1/solar-data/batch-submit
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "solar_data_array": [
    {
      "solar_flux": 150.2,
      "k_index": 2,
      "a_index": 8,
      "timestamp": "2024-01-15T10:30:00Z"
    },
    {
      "solar_flux": 148.5,
      "k_index": 3,
      "a_index": 10,
      "timestamp": "2024-01-15T11:00:00Z"
    }
  ]
}
```

#### **Update Solar Data**
```http
PUT /api/v1/solar-data/update
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "solar_flux": 152.1,
  "k_index": 1,
  "a_index": 6,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Weather Data API

### **Weather Data Integration**

> **Note**: All Weather Data API endpoints are controlled by feature toggles. See [Feature Toggle API Control](FEATURE_TOGGLE_API_CONTROL.md) for configuration details.

The Weather Data API provides atmospheric condition effects on radio propagation. This system fetches weather data from multiple sources and uses it to simulate realistic atmospheric effects that affect radio communication across different frequency bands.

### **Weather Data API Endpoints**

**Base URL**: `http://localhost:8080/api/v1/weather-data`

#### **Get Current Weather Conditions**
```http
GET /api/v1/weather-data/current
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "weather_conditions": {
    "temperature_celsius": 20.0,
    "humidity_percent": 50.0,
    "pressure_hpa": 1013.25,
    "wind_speed_ms": 5.0,
    "wind_direction_deg": 180.0,
    "precipitation_mmh": 0.0,
    "dew_point_celsius": 10.0,
    "visibility_km": 10.0,
    "cloud_cover_percent": 30.0,
    "uv_index": 5.0,
    "air_quality_index": 50.0,
    "pollen_count": 25.0,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### **Submit Weather Data from Game**
```http
POST /api/v1/weather-data/submit
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "temperature_celsius": 22.5,
  "humidity_percent": 65.0,
  "pressure_hpa": 1015.2,
  "wind_speed_ms": 8.5,
  "wind_direction_deg": 270.0,
  "precipitation_mmh": 2.5,
  "visibility_km": 8.0,
  "cloud_cover_percent": 75.0,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Weather data submitted successfully",
  "data_id": "weather_20240115_103000",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Lightning Data API

### **Lightning Data Integration**

> **Note**: All Lightning Data API endpoints are controlled by feature toggles. See [Feature Toggle API Control](FEATURE_TOGGLE_API_CONTROL.md) for configuration details.

The Lightning Data API provides real-time atmospheric noise simulation from lightning strikes. This system processes lightning data to simulate realistic atmospheric noise that affects radio communication quality.

## Substation and Power Plant API

### **Substation and Power Plant Data Integration**

> **Note**: All Substation and Power Plant API endpoints are controlled by feature toggles. See [Feature Toggle API Control](FEATURE_TOGGLE_API_CONTROL.md) for configuration details.

The Substation and Power Plant API provides real-time electrical infrastructure data for enhanced noise floor calculations. This system integrates with Open Infrastructure Map data source to provide comprehensive electrical infrastructure information including substations, power stations, and transmission lines.

### **Substation API Endpoints**

**Base URL**: `http://localhost:8080/api/v1/substation-data`

#### **Get Current Substation Data**
```http
GET /api/v1/substation-data/current?latitude=40.7128&longitude=-74.0060&radius_km=50.0
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "substation_data": {
    "substations": [
      {
        "substation_id": "substation_001",
        "substation_type": "transmission",
        "latitude": 40.7128,
        "longitude": -74.0060,
        "voltage_kv": 345.0,
        "capacity_mva": 500.0,
        "is_fenced": true,
        "operator_name": "ConEd",
        "noise_factor": 1.0,
        "is_active": true,
        "last_updated": "2024-01-15T10:30:00Z"
      }
    ],
    "total_count": 1,
    "search_radius_km": 50.0,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### **Submit Substation Data from Game**
```http
POST /api/v1/substation-data/submit
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "substation_id": "game_substation_001",
  "substation_type": "distribution",
  "latitude": 40.7128,
  "longitude": -74.0060,
  "voltage_kv": 12.0,
  "capacity_mva": 50.0,
  "is_fenced": false,
  "operator_name": "Game Utility",
  "noise_factor": 1.2,
  "is_active": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Substation data submitted successfully",
  "data_id": "substation_20240115_103000",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### **Submit Batch Substation Data**
```http
POST /api/v1/substation-data/batch-submit
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "substation_data_array": [
    {
      "substation_id": "game_substation_001",
      "substation_type": "distribution",
      "latitude": 40.7128,
      "longitude": -74.0060,
      "voltage_kv": 12.0,
      "capacity_mva": 50.0,
      "timestamp": "2024-01-15T10:30:00Z"
    },
    {
      "substation_id": "game_substation_002",
      "substation_type": "transmission",
      "latitude": 40.7200,
      "longitude": -74.0100,
      "voltage_kv": 345.0,
      "capacity_mva": 500.0,
      "timestamp": "2024-01-15T10:30:00Z"
    }
  ]
}
```

#### **Update Substation Data**
```http
PUT /api/v1/substation-data/update
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "substation_id": "game_substation_001",
  "voltage_kv": 13.8,
  "capacity_mva": 75.0,
  "is_active": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Power Plant API Endpoints**

**Base URL**: `http://localhost:8080/api/v1/power-plant-data`

#### **Get Current Power Plant Data**
```http
GET /api/v1/power-plant-data/current?latitude=40.7128&longitude=-74.0060&radius_km=50.0
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "power_plant_data": {
    "power_plants": [
      {
        "station_id": "power_plant_001",
        "station_type": "thermal",
        "latitude": 40.7128,
        "longitude": -74.0060,
        "capacity_mw": 1000.0,
        "current_output_mw": 850.0,
        "is_fenced": true,
        "operator_name": "PSEG",
        "noise_factor": 1.0,
        "is_active": true,
        "last_updated": "2024-01-15T10:30:00Z"
      }
    ],
    "total_count": 1,
    "search_radius_km": 50.0,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### **Submit Power Plant Data from Game**
```http
POST /api/v1/power-plant-data/submit
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "station_id": "game_power_plant_001",
  "station_type": "nuclear",
  "latitude": 40.7128,
  "longitude": -74.0060,
  "capacity_mw": 2000.0,
  "current_output_mw": 1800.0,
  "is_fenced": true,
  "operator_name": "Game Power Corp",
  "noise_factor": 1.5,
  "is_active": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Power plant data submitted successfully",
  "data_id": "power_plant_20240115_103000",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### **Submit Batch Power Plant Data**
```http
POST /api/v1/power-plant-data/batch-submit
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "power_plant_data_array": [
    {
      "station_id": "game_power_plant_001",
      "station_type": "thermal",
      "latitude": 40.7128,
      "longitude": -74.0060,
      "capacity_mw": 1000.0,
      "current_output_mw": 850.0,
      "timestamp": "2024-01-15T10:30:00Z"
    },
    {
      "station_id": "game_power_plant_002",
      "station_type": "wind",
      "latitude": 40.7200,
      "longitude": -74.0100,
      "capacity_mw": 500.0,
      "current_output_mw": 300.0,
      "timestamp": "2024-01-15T10:30:00Z"
    }
  ]
}
```

#### **Update Power Plant Data**
```http
PUT /api/v1/power-plant-data/update
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "station_id": "game_power_plant_001",
  "current_output_mw": 900.0,
  "is_active": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Game Integration Examples**

#### **1. Substation Data Integration**
```cpp
// C++ substation data integration example
class SubstationDataIntegration {
private:
    std::string api_base_url = "http://localhost:8080/api/v1/substation-data";
    
public:
    // Submit substation data from game
    bool submitSubstationData(const std::string& substation_id,
                             const std::string& substation_type,
                             double latitude, double longitude,
                             float voltage_kv, float capacity_mva,
                             bool is_fenced, const std::string& operator_name) {
        nlohmann::json request_data = {
            {"substation_id", substation_id},
            {"substation_type", substation_type},
            {"latitude", latitude},
            {"longitude", longitude},
            {"voltage_kv", voltage_kv},
            {"capacity_mva", capacity_mva},
            {"is_fenced", is_fenced},
            {"operator_name", operator_name},
            {"noise_factor", 1.0f},
            {"is_active", true}
        };
        
        httplib::Client client("localhost", 8080);
        auto res = client.Post("/api/v1/substation-data/submit", 
                               request_data.dump(), "application/json");
        
        if (res && res->status == 200) {
            auto response = nlohmann::json::parse(res->body);
            return response["success"];
        }
        return false;
    }
    
    // Submit batch substation data
    bool submitBatchSubstationData(const std::vector<SubstationData>& data_array) {
        nlohmann::json request_data;
        nlohmann::json substation_array = nlohmann::json::array();
        
        for (const auto& data : data_array) {
            nlohmann::json entry = {
                {"substation_id", data.substation_id},
                {"substation_type", data.substation_type},
                {"latitude", data.latitude},
                {"longitude", data.longitude},
                {"voltage_kv", data.voltage_kv},
                {"capacity_mva", data.capacity_mva},
                {"is_fenced", data.is_fenced},
                {"operator_name", data.operator_name}
            };
            substation_array.push_back(entry);
        }
        
        request_data["substation_data_array"] = substation_array;
        
        httplib::Client client("localhost", 8080);
        auto res = client.Post("/api/v1/substation-data/batch-submit", 
                               request_data.dump(), "application/json");
        
        if (res && res->status == 200) {
            auto response = nlohmann::json::parse(res->body);
            return response["success"];
        }
        return false;
    }
    
    // Get nearby substations
    std::vector<SubstationData> getNearbySubstations(double latitude, double longitude, 
                                                    float radius_km = 50.0f) {
        std::stringstream url;
        url << "/api/v1/substation-data/current?latitude=" << latitude 
            << "&longitude=" << longitude << "&radius_km=" << radius_km;
        
        httplib::Client client("localhost", 8080);
        auto res = client.Get(url.str().c_str());
        
        std::vector<SubstationData> substations;
        
        if (res && res->status == 200) {
            auto response = nlohmann::json::parse(res->body);
            if (response["success"]) {
                auto substation_data = response["substation_data"];
                for (const auto& substation : substation_data["substations"]) {
                    SubstationData data;
                    data.substation_id = substation["substation_id"];
                    data.substation_type = substation["substation_type"];
                    data.latitude = substation["latitude"];
                    data.longitude = substation["longitude"];
                    data.voltage_kv = substation["voltage_kv"];
                    data.capacity_mva = substation["capacity_mva"];
                    data.is_fenced = substation["is_fenced"];
                    data.operator_name = substation["operator_name"];
                    substations.push_back(data);
                }
            }
        }
        
        return substations;
    }
};
```

#### **2. Power Plant Data Integration**
```cpp
// C++ power plant data integration example
class PowerPlantDataIntegration {
private:
    std::string api_base_url = "http://localhost:8080/api/v1/power-plant-data";
    
public:
    // Submit power plant data from game
    bool submitPowerPlantData(const std::string& station_id,
                             const std::string& station_type,
                             double latitude, double longitude,
                             float capacity_mw, float current_output_mw,
                             bool is_fenced, const std::string& operator_name) {
        nlohmann::json request_data = {
            {"station_id", station_id},
            {"station_type", station_type},
            {"latitude", latitude},
            {"longitude", longitude},
            {"capacity_mw", capacity_mw},
            {"current_output_mw", current_output_mw},
            {"is_fenced", is_fenced},
            {"operator_name", operator_name},
            {"noise_factor", 1.0f},
            {"is_active", true}
        };
        
        httplib::Client client("localhost", 8080);
        auto res = client.Post("/api/v1/power-plant-data/submit", 
                               request_data.dump(), "application/json");
        
        if (res && res->status == 200) {
            auto response = nlohmann::json::parse(res->body);
            return response["success"];
        }
        return false;
    }
    
    // Submit batch power plant data
    bool submitBatchPowerPlantData(const std::vector<PowerPlantData>& data_array) {
        nlohmann::json request_data;
        nlohmann::json power_plant_array = nlohmann::json::array();
        
        for (const auto& data : data_array) {
            nlohmann::json entry = {
                {"station_id", data.station_id},
                {"station_type", data.station_type},
                {"latitude", data.latitude},
                {"longitude", data.longitude},
                {"capacity_mw", data.capacity_mw},
                {"current_output_mw", data.current_output_mw},
                {"is_fenced", data.is_fenced},
                {"operator_name", data.operator_name}
            };
            power_plant_array.push_back(entry);
        }
        
        request_data["power_plant_data_array"] = power_plant_array;
        
        httplib::Client client("localhost", 8080);
        auto res = client.Post("/api/v1/power-plant-data/batch-submit", 
                               request_data.dump(), "application/json");
        
        if (res && res->status == 200) {
            auto response = nlohmann::json::parse(res->body);
            return response["success"];
        }
        return false;
    }
    
    // Get nearby power plants
    std::vector<PowerPlantData> getNearbyPowerPlants(double latitude, double longitude, 
                                                    float radius_km = 50.0f) {
        std::stringstream url;
        url << "/api/v1/power-plant-data/current?latitude=" << latitude 
            << "&longitude=" << longitude << "&radius_km=" << radius_km;
        
        httplib::Client client("localhost", 8080);
        auto res = client.Get(url.str().c_str());
        
        std::vector<PowerPlantData> power_plants;
        
        if (res && res->status == 200) {
            auto response = nlohmann::json::parse(res->body);
            if (response["success"]) {
                auto power_plant_data = response["power_plant_data"];
                for (const auto& plant : power_plant_data["power_plants"]) {
                    PowerPlantData data;
                    data.station_id = plant["station_id"];
                    data.station_type = plant["station_type"];
                    data.latitude = plant["latitude"];
                    data.longitude = plant["longitude"];
                    data.capacity_mw = plant["capacity_mw"];
                    data.current_output_mw = plant["current_output_mw"];
                    data.is_fenced = plant["is_fenced"];
                    data.operator_name = plant["operator_name"];
                    power_plants.push_back(data);
                }
            }
        }
        
        return power_plants;
    }
};
```

#### **3. Electrical Infrastructure Noise Effects**
```cpp
// Electrical infrastructure noise effects integration
class ElectricalInfrastructureNoise {
private:
    SubstationDataIntegration substation_integration;
    PowerPlantDataIntegration power_plant_integration;
    
public:
    // Calculate electrical infrastructure noise effects
    float calculateElectricalNoiseEffects(double latitude, double longitude, 
                                         float frequency_hz, float distance_km) {
        float total_noise_effect = 0.0f;
        
        // Get nearby substations
        auto substations = substation_integration.getNearbySubstations(latitude, longitude, 50.0f);
        for (const auto& substation : substations) {
            float substation_noise = calculateSubstationNoise(substation, frequency_hz, distance_km);
            total_noise_effect += substation_noise;
        }
        
        // Get nearby power plants
        auto power_plants = power_plant_integration.getNearbyPowerPlants(latitude, longitude, 50.0f);
        for (const auto& plant : power_plants) {
            float plant_noise = calculatePowerPlantNoise(plant, frequency_hz, distance_km);
            total_noise_effect += plant_noise;
        }
        
        return total_noise_effect;
    }
    
    // Calculate substation noise contribution
    float calculateSubstationNoise(const SubstationData& substation, 
                                   float frequency_hz, float distance_km) {
        float base_noise = 0.0f;
        
        // Voltage-based noise calculation
        if (substation.voltage_kv > 100.0f) {
            base_noise = 10.0f; // High voltage substations
        } else if (substation.voltage_kv > 50.0f) {
            base_noise = 5.0f;  // Medium voltage substations
        } else {
            base_noise = 2.0f;  // Low voltage substations
        }
        
        // Distance attenuation
        float distance_effect = 20.0f * log10(distance_km + 1.0f);
        
        // Fencing effect
        float fencing_effect = substation.is_fenced ? -3.0f : 0.0f;
        
        // Frequency-dependent effects
        float frequency_effect = 0.0f;
        if (frequency_hz < 1000000.0f) { // VLF/LF
            frequency_effect = 2.0f;
        } else if (frequency_hz < 100000000.0f) { // MF/HF
            frequency_effect = 1.0f;
        } else if (frequency_hz < 1000000000.0f) { // VHF/UHF
            frequency_effect = 0.5f;
        }
        
        return base_noise - distance_effect + fencing_effect + frequency_effect;
    }
    
    // Calculate power plant noise contribution
    float calculatePowerPlantNoise(const PowerPlantData& plant, 
                                  float frequency_hz, float distance_km) {
        float base_noise = 0.0f;
        
        // Capacity-based noise calculation
        if (plant.capacity_mw > 1000.0f) {
            base_noise = 15.0f; // Large power plants
        } else if (plant.capacity_mw > 100.0f) {
            base_noise = 10.0f; // Medium power plants
        } else {
            base_noise = 5.0f;  // Small power plants
        }
        
        // Output level effect
        float output_factor = plant.current_output_mw / plant.capacity_mw;
        base_noise *= output_factor;
        
        // Distance attenuation
        float distance_effect = 20.0f * log10(distance_km + 1.0f);
        
        // Fencing effect
        float fencing_effect = plant.is_fenced ? -5.0f : 0.0f;
        
        // Frequency-dependent effects
        float frequency_effect = 0.0f;
        if (frequency_hz < 1000000.0f) { // VLF/LF
            frequency_effect = 3.0f;
        } else if (frequency_hz < 100000000.0f) { // MF/HF
            frequency_effect = 2.0f;
        } else if (frequency_hz < 1000000000.0f) { // VHF/UHF
            frequency_effect = 1.0f;
        }
        
        return base_noise - distance_effect + fencing_effect + frequency_effect;
    }
};
```

### **Lightning Data API Endpoints**

**Base URL**: `http://localhost:8080/api/v1/lightning-data`

#### **Get Current Lightning Data**
```http
GET /api/v1/lightning-data/current
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "lightning_data": {
    "total_strikes": 1250,
    "strikes_per_minute": 15.2,
    "average_distance_km": 25.5,
    "noise_level_db": -45.2,
    "atmospheric_noise": {
      "vlf_noise_db": -52.1,
      "lf_noise_db": -48.3,
      "mf_noise_db": -45.2,
      "hf_noise_db": -42.8
    },
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### **Submit Lightning Data from Game**
```http
POST /api/v1/lightning-data/submit
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "strikes_count": 25,
  "average_distance_km": 15.5,
  "intensity_level": "moderate",
  "noise_contribution_db": -38.5,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Lightning data submitted successfully",
  "data_id": "lightning_20240115_103000",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### **Submit Batch Lightning Data**
```http
POST /api/v1/lightning-data/batch-submit
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "lightning_data_array": [
    {
      "strikes_count": 25,
      "average_distance_km": 15.5,
      "intensity_level": "moderate",
      "timestamp": "2024-01-15T10:30:00Z"
    },
    {
      "strikes_count": 18,
      "average_distance_km": 22.3,
      "intensity_level": "light",
      "timestamp": "2024-01-15T11:00:00Z"
    }
  ]
}
```

### **Game Integration Examples**

#### **1. Solar Effects on Radio Propagation**
```cpp
// C++ solar data integration example
class SolarRadioEffects {
private:
    std::string api_base_url = "http://localhost:8080/api/v1/solar-data";
    
public:
    // Submit solar data from game
    bool submitSolarData(float solar_flux, int k_index, int a_index) {
        nlohmann::json request_data = {
            {"solar_flux", solar_flux},
            {"k_index", k_index},
            {"a_index", a_index}
        };
        
        // Make HTTP POST request
        httplib::Client client("localhost", 8080);
        auto res = client.Post("/api/v1/solar-data/submit", 
                               request_data.dump(), "application/json");
        
        if (res && res->status == 200) {
            auto response = nlohmann::json::parse(res->body);
            return response["status"] == "success";
        }
        return false;
    }
    
    // Submit batch solar data
    bool submitBatchSolarData(const std::vector<SolarData>& data_array) {
        nlohmann::json request_data;
        nlohmann::json solar_array = nlohmann::json::array();
        
        for (const auto& data : data_array) {
            nlohmann::json entry = {
                {"solar_flux", data.solar_flux},
                {"k_index", data.k_index},
                {"a_index", data.a_index}
            };
            solar_array.push_back(entry);
        }
        
        request_data["solar_data_array"] = solar_array;
        
        httplib::Client client("localhost", 8080);
        auto res = client.Post("/api/v1/solar-data/batch-submit", 
                               request_data.dump(), "application/json");
        
        if (res && res->status == 200) {
            auto response = nlohmann::json::parse(res->body);
            return response["status"] == "success";
        }
        return false;
    }
    
    // Update solar data
    bool updateSolarData(float solar_flux, int k_index) {
        nlohmann::json request_data = {
            {"solar_flux", solar_flux},
            {"k_index", k_index}
        };
        
        httplib::Client client("localhost", 8080);
        auto res = client.Put("/api/v1/solar-data/update", 
                              request_data.dump(), "application/json");
        
        if (res && res->status == 200) {
            auto response = nlohmann::json::parse(res->body);
            return response["status"] == "success";
        }
        return false;
    }
    
    // Get current solar data
    SolarData getCurrentSolarData() {
        httplib::Client client("localhost", 8080);
        auto res = client.Get("/api/v1/solar-data/current");
        
        if (res && res->status == 200) {
            auto response = nlohmann::json::parse(res->body);
            if (response["status"] == "success") {
                auto solar_data = response["solar_data"];
                return SolarData{
                    solar_data["solar_flux"],
                    solar_data["k_index"],
                    solar_data["a_index"]
                };
            }
        }
        return SolarData{0, 0, 0}; // Default values
    }
    
    // Get solar effects on radio propagation
    float getSolarEffects(float frequency_hz, float latitude, float longitude) {
        // Get current solar data
        auto solar_response = sendAPIRequest("GET", "/current", {});
        auto solar_data = solar_response["solar_data"];
        
        // Calculate solar effects
        float solar_flux_effect = calculateSolarFluxEffect(frequency_hz, solar_data["solar_flux"]);
        float geomagnetic_effect = calculateGeomagneticEffect(frequency_hz, solar_data["k_index"]);
        float latitude_effect = calculateLatitudeEffect(frequency_hz, latitude);
        
        return solar_flux_effect + geomagnetic_effect + latitude_effect;
    }
    
    // Calculate solar flux effects on HF propagation
    float calculateSolarFluxEffect(float frequency_hz, float solar_flux) {
        if (frequency_hz >= 3000000.0f && frequency_hz <= 30000000.0f) { // HF band
            // Solar flux affects HF propagation
            float flux_factor = (solar_flux - 70.0f) / 100.0f;
            return flux_factor * 2.0f; // dB effect
        }
        return 0.0f;
    }
    
    // Calculate geomagnetic effects
    float calculateGeomagneticEffect(float frequency_hz, float k_index) {
        if (frequency_hz >= 3000000.0f && frequency_hz <= 30000000.0f) { // HF band
            // K-index affects HF propagation
            if (k_index > 5.0f) {
                return -(k_index - 5.0f) * 3.0f; // Negative effect on propagation
            }
        }
        return 0.0f;
    }
    
    // Calculate latitude-dependent effects
    float calculateLatitudeEffect(float frequency_hz, float latitude) {
        if (frequency_hz >= 3000000.0f && frequency_hz <= 30000000.0f) { // HF band
            // Latitude affects ionospheric propagation
            float lat_factor = (90.0f - abs(latitude)) / 90.0f;
            return lat_factor * 1.5f; // dB effect
        }
        return 0.0f;
    }
};
```

#### **2. Solar Activity Monitoring**
```cpp
// Solar activity monitoring for game integration
class SolarActivityMonitor {
private:
    float last_solar_flux;
    float last_k_index;
    std::chrono::system_clock::time_point last_update;
    
public:
    // Monitor solar activity changes
    bool hasSolarActivityChanged() {
        auto current_response = sendAPIRequest("GET", "/current", {});
        auto current_data = current_response["solar_data"];
        
        float current_solar_flux = current_data["solar_flux"];
        float current_k_index = current_data["k_index"];
        
        bool changed = (abs(current_solar_flux - last_solar_flux) > 5.0f) ||
                      (abs(current_k_index - last_k_index) > 1.0f);
        
        if (changed) {
            last_solar_flux = current_solar_flux;
            last_k_index = current_k_index;
            last_update = std::chrono::system_clock::now();
        }
        
        return changed;
    }
    
    // Get propagation forecast
    std::string getPropagationForecast() {
        auto current_response = sendAPIRequest("GET", "/current", {});
        auto current_data = current_response["solar_data"];
        
        float solar_flux = current_data["solar_flux"];
        float k_index = current_data["k_index"];
        
        if (solar_flux > 150.0f && k_index < 3.0f) {
            return "excellent";
        } else if (solar_flux > 100.0f && k_index < 5.0f) {
            return "good";
        } else if (solar_flux > 70.0f && k_index < 7.0f) {
            return "fair";
        } else {
            return "poor";
        }
    }
};
```

## AGC & Squelch API

### **AGC & Squelch System Integration**

The AGC & Squelch API provides advanced Automatic Gain Control and Squelch functionality with configurable presets. This system ensures optimal audio quality and communication reliability by automatically adjusting gain levels and managing signal thresholds.

### **AGC & Squelch API Endpoints**

**Base URL**: `http://localhost:8080/api/v1/agc-squelch`

#### **Get AGC Status**
```http
GET /api/v1/agc-squelch/agc/status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "agc_status": {
    "enabled": true,
    "mode": "automatic",
    "current_gain_db": 15.2,
    "target_gain_db": 15.0,
    "max_gain_db": 30.0,
    "min_gain_db": 0.0,
    "target_level_db": -20.0,
    "threshold_db": -80.0,
    "attack_time_ms": 10.0,
    "release_time_ms": 100.0,
    "efficiency_percent": 85.2,
    "agc_active": true,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### **Get Squelch Status**
```http
GET /api/v1/agc-squelch/squelch/status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "squelch_status": {
    "enabled": true,
    "type": "signal",
    "threshold_db": -85.0,
    "hysteresis_db": 3.0,
    "attack_time_ms": 5.0,
    "release_time_ms": 50.0,
    "signal_strength_db": -82.0,
    "noise_floor_db": -95.0,
    "signal_to_noise_ratio_db": 13.0,
    "squelch_open": true,
    "tone_squelch_enabled": false,
    "digital_squelch_enabled": false,
    "efficiency_percent": 92.5,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### **Set AGC Parameters**
```http
POST /api/v1/agc-squelch/agc/configure
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "mode": "automatic",
  "target_level_db": -20.0,
  "threshold_db": -80.0,
  "attack_time_ms": 10.0,
  "release_time_ms": 100.0,
  "max_gain_db": 30.0,
  "min_gain_db": 0.0
}
```

#### **Set Squelch Parameters**
```http
POST /api/v1/agc-squelch/squelch/configure
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "type": "signal",
  "threshold_db": -85.0,
  "hysteresis_db": 3.0,
  "attack_time_ms": 5.0,
  "release_time_ms": 50.0
}
```

### **CTCSS (Continuous Tone-Coded Squelch System) Integration**

#### **Enable CTCSS Tone Squelch**
```http
POST /api/v1/agc-squelch/squelch/tone-squelch
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "enabled": true,
  "tone_frequency_hz": 100.0,
  "tone_tolerance_hz": 2.0,
  "tone_filter_bandwidth_hz": 10.0
}
```

**Response:**
```json
{
  "success": true,
  "message": "CTCSS tone squelch enabled",
  "tone_frequency_hz": 100.0,
  "tone_detected": false,
  "tone_strength_db": 0.0,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### **Available CTCSS Tones**
```json
{
  "success": true,
  "ctcss_tones": [
    {"frequency": 67.0, "description": "CTCSS 67.0 Hz"},
    {"frequency": 69.3, "description": "CTCSS 69.3 Hz"},
    {"frequency": 71.9, "description": "CTCSS 71.9 Hz"},
    {"frequency": 74.4, "description": "CTCSS 74.4 Hz"},
    {"frequency": 77.0, "description": "CTCSS 77.0 Hz"},
    {"frequency": 79.7, "description": "CTCSS 79.7 Hz"},
    {"frequency": 82.5, "description": "CTCSS 82.5 Hz"},
    {"frequency": 85.4, "description": "CTCSS 85.4 Hz"},
    {"frequency": 88.5, "description": "CTCSS 88.5 Hz"},
    {"frequency": 91.5, "description": "CTCSS 91.5 Hz"},
    {"frequency": 94.8, "description": "CTCSS 94.8 Hz"},
    {"frequency": 97.4, "description": "CTCSS 97.4 Hz"},
    {"frequency": 100.0, "description": "CTCSS 100.0 Hz"},
    {"frequency": 103.5, "description": "CTCSS 103.5 Hz"},
    {"frequency": 107.2, "description": "CTCSS 107.2 Hz"},
    {"frequency": 110.9, "description": "CTCSS 110.9 Hz"},
    {"frequency": 114.8, "description": "CTCSS 114.8 Hz"},
    {"frequency": 118.8, "description": "CTCSS 118.8 Hz"},
    {"frequency": 123.0, "description": "CTCSS 123.0 Hz"},
    {"frequency": 127.3, "description": "CTCSS 127.3 Hz"},
    {"frequency": 131.8, "description": "CTCSS 131.8 Hz"},
    {"frequency": 136.5, "description": "CTCSS 136.5 Hz"},
    {"frequency": 141.3, "description": "CTCSS 141.3 Hz"},
    {"frequency": 146.2, "description": "CTCSS 146.2 Hz"},
    {"frequency": 151.4, "description": "CTCSS 151.4 Hz"},
    {"frequency": 156.7, "description": "CTCSS 156.7 Hz"},
    {"frequency": 162.2, "description": "CTCSS 162.2 Hz"},
    {"frequency": 167.9, "description": "CTCSS 167.9 Hz"},
    {"frequency": 173.8, "description": "CTCSS 173.8 Hz"},
    {"frequency": 179.9, "description": "CTCSS 179.9 Hz"},
    {"frequency": 186.2, "description": "CTCSS 186.2 Hz"},
    {"frequency": 192.8, "description": "CTCSS 192.8 Hz"},
    {"frequency": 203.5, "description": "CTCSS 203.5 Hz"},
    {"frequency": 210.7, "description": "CTCSS 210.7 Hz"},
    {"frequency": 218.1, "description": "CTCSS 218.1 Hz"},
    {"frequency": 225.7, "description": "CTCSS 225.7 Hz"},
    {"frequency": 233.6, "description": "CTCSS 233.6 Hz"},
    {"frequency": 241.8, "description": "CTCSS 241.8 Hz"},
    {"frequency": 250.3, "description": "CTCSS 250.3 Hz"}
  ]
}
```

### **Game Integration Examples**

#### **1. AGC & Squelch Integration**
```cpp
// C++ AGC & Squelch integration example
class AGC_Squelch_Integration {
private:
    std::string api_base_url = "http://localhost:8080/api/v1/agc-squelch";
    
public:
    // Configure AGC for optimal audio quality
    bool configureAGC(float target_level_db, float threshold_db, 
                      float attack_time_ms, float release_time_ms) {
        nlohmann::json request = {
            {"mode", "automatic"},
            {"target_level_db", target_level_db},
            {"threshold_db", threshold_db},
            {"attack_time_ms", attack_time_ms},
            {"release_time_ms", release_time_ms},
            {"max_gain_db", 30.0},
            {"min_gain_db", 0.0}
        };
        
        auto response = sendAPIRequest("POST", "/agc/configure", request);
        return response["success"];
    }
    
    // Configure squelch for noise reduction
    bool configureSquelch(float threshold_db, float hysteresis_db,
                         float attack_time_ms, float release_time_ms) {
        nlohmann::json request = {
            {"type", "signal"},
            {"threshold_db", threshold_db},
            {"hysteresis_db", hysteresis_db},
            {"attack_time_ms", attack_time_ms},
            {"release_time_ms", release_time_ms}
        };
        
        auto response = sendAPIRequest("POST", "/squelch/configure", request);
        return response["success"];
    }
    
    // Get current AGC status
    AGCStatus getAGCStatus() {
        auto response = sendAPIRequest("GET", "/agc/status", {});
        AGCStatus status;
        
        if (response["success"]) {
            auto agc_data = response["agc_status"];
            status.enabled = agc_data["enabled"];
            status.mode = agc_data["mode"];
            status.current_gain_db = agc_data["current_gain_db"];
            status.efficiency_percent = agc_data["efficiency_percent"];
            status.agc_active = agc_data["agc_active"];
        }
        
        return status;
    }
    
    // Get current squelch status
    SquelchStatus getSquelchStatus() {
        auto response = sendAPIRequest("GET", "/squelch/status", {});
        SquelchStatus status;
        
        if (response["success"]) {
            auto squelch_data = response["squelch_status"];
            status.enabled = squelch_data["enabled"];
            status.type = squelch_data["type"];
            status.threshold_db = squelch_data["threshold_db"];
            status.squelch_open = squelch_data["squelch_open"];
            status.signal_strength_db = squelch_data["signal_strength_db"];
            status.efficiency_percent = squelch_data["efficiency_percent"];
        }
        
        return status;
    }
};
```

#### **2. CTCSS Tone Squelch Integration**
```cpp
// CTCSS tone squelch integration
class CTCSS_Integration {
private:
    std::string api_base_url = "http://localhost:8080/api/v1/agc-squelch";
    
public:
    // Enable CTCSS tone squelch
    bool enableCTCSS(float tone_frequency_hz, float tolerance_hz) {
        nlohmann::json request = {
            {"enabled", true},
            {"tone_frequency_hz", tone_frequency_hz},
            {"tone_tolerance_hz", tolerance_hz},
            {"tone_filter_bandwidth_hz", 10.0}
        };
        
        auto response = sendAPIRequest("POST", "/squelch/tone-squelch", request);
        return response["success"];
    }
    
    // Disable CTCSS tone squelch
    bool disableCTCSS() {
        nlohmann::json request = {
            {"enabled", false}
        };
        
        auto response = sendAPIRequest("POST", "/squelch/tone-squelch", request);
        return response["success"];
    }
    
    // Check if CTCSS tone is detected
    bool isCTCSToneDetected() {
        auto response = sendAPIRequest("GET", "/squelch/status", {});
        
        if (response["success"]) {
            auto squelch_data = response["squelch_status"];
            return squelch_data["tone_detected"];
        }
        
        return false;
    }
    
    // Get available CTCSS tones
    std::vector<float> getAvailableCTCSTones() {
        auto response = sendAPIRequest("GET", "/squelch/ctcss-tones", {});
        std::vector<float> tones;
        
        if (response["success"]) {
            auto tones_data = response["ctcss_tones"];
            for (const auto& tone : tones_data) {
                tones.push_back(tone["frequency"]);
            }
        }
        
        return tones;
    }
    
    // Set CTCSS tone for specific frequency
    bool setCTCSTone(float tone_frequency_hz) {
        // Validate tone frequency
        auto available_tones = getAvailableCTCSTones();
        bool valid_tone = false;
        
        for (float tone : available_tones) {
            if (abs(tone - tone_frequency_hz) < 0.1f) {
                valid_tone = true;
                break;
            }
        }
        
        if (!valid_tone) {
            return false;
        }
        
        return enableCTCSS(tone_frequency_hz, 2.0f);
    }
};
```

#### **3. Audio Quality Monitoring**
```cpp
// Audio quality monitoring for game integration
class AudioQualityMonitor {
private:
    std::string api_base_url = "http://localhost:8080/api/v1/agc-squelch";
    
public:
    // Monitor audio quality
    AudioQuality getAudioQuality() {
        auto agc_response = sendAPIRequest("GET", "/agc/status", {});
        auto squelch_response = sendAPIRequest("GET", "/squelch/status", {});
        
        AudioQuality quality;
        
        if (agc_response["success"] && squelch_response["success"]) {
            auto agc_data = agc_response["agc_status"];
            auto squelch_data = squelch_response["squelch_status"];
            
            quality.agc_efficiency = agc_data["efficiency_percent"];
            quality.squelch_efficiency = squelch_data["efficiency_percent"];
            quality.signal_strength = squelch_data["signal_strength_db"];
            quality.noise_floor = squelch_data["noise_floor_db"];
            quality.signal_to_noise_ratio = squelch_data["signal_to_noise_ratio_db"];
            quality.overall_quality = (quality.agc_efficiency + quality.squelch_efficiency) / 200.0f;
        }
        
        return quality;
    }
    
    // Check if audio quality is optimal
    bool isAudioQualityOptimal() {
        AudioQuality quality = getAudioQuality();
        
        return quality.overall_quality > 0.8f && 
               quality.signal_to_noise_ratio > 10.0f &&
               quality.agc_efficiency > 80.0f &&
               quality.squelch_efficiency > 80.0f;
    }
    
    // Get audio quality recommendations
    std::string getAudioQualityRecommendations() {
        AudioQuality quality = getAudioQuality();
        
        if (quality.overall_quality < 0.6f) {
            return "Poor audio quality. Check signal strength and noise levels.";
        } else if (quality.overall_quality < 0.8f) {
            return "Fair audio quality. Consider adjusting AGC or squelch settings.";
        } else {
            return "Good audio quality. System is operating optimally.";
        }
    }
};
```

## FGCom-mumble Data Output

### **Audio Data Output**

FGCom-mumble provides processed audio data back to the game:

**Audio Channels:**
- **COM1**: Primary communication channel
- **COM2**: Secondary communication channel
- **COM3**: Tertiary communication channel
- **INTERCOM**: Internal communication

**Audio Effects:**
- **Static**: Atmospheric noise simulation
- **Interference**: Radio frequency interference
- **Distance Attenuation**: Signal strength based on distance
- **Propagation Effects**: Ionospheric and tropospheric effects

### **Signal Quality Data**

FGCom-mumble provides real-time signal quality information:

```
SIGNAL_QUALITY=0.0-1.0
SIGNAL_STRENGTH=dBm
NOISE_LEVEL=dBm
SNR=dB
```

### **Communication Status**

```
COMM_STATUS=active|inactive
ACTIVE_FREQUENCIES=freq1,freq2,freq3
RECEIVING_FROM=callsign1,callsign2
```

## Integration Examples

### **1. FlightGear Integration (Native)**

**File Structure:**
```
client/fgfs-addon/
├── addon-main.nas          # Main addon logic
├── radios.nas             # Radio system implementation
├── intercom.nas           # Intercom system
└── gui/                   # User interface components
```

**Key Implementation:**
```nasal
# FlightGear Nasal script example
var fgcom_mumble = {
    init: func() {
        # Initialize UDP connection
        self.udp_client = UDPClient.new("localhost", 16661);
    },
    
    update_radio: func(radio_num, freq, ptt, power) {
        var data = "COM" ~ radio_num ~ "_FRQ=" ~ freq ~ 
                   ",COM" ~ radio_num ~ "_PTT=" ~ ptt ~
                   ",COM" ~ radio_num ~ "_PWR=" ~ power;
        self.udp_client.send(data);
    }
};
```

### **2. Microsoft Flight Simulator Integration (RadioGUI)**

**SimConnect Integration:**
```cpp
// C++ SimConnect integration
class MSFSIntegration {
private:
    HANDLE hSimConnect;
    
public:
    void InitializeSimConnect();
    void UpdateRadioData();
    void SendToFGComMumble();
};

void MSFSIntegration::UpdateRadioData() {
    // Get radio data from SimConnect
    SIMCONNECT_DATA_RADIO_STACK radioData;
    SimConnect_GetDataOnSimObject(hSimConnect, 
        SIMCONNECT_DATA_RADIO_STACK_ID, 
        SIMCONNECT_OBJECT_ID_USER, 
        SIMCONNECT_PERIOD_ONCE, 
        &radioData);
    
    // Send to FGCom-mumble
    SendToFGComMumble(radioData);
}
```

### **3. Custom Game Integration (API)**

**RESTful API Integration:**
```cpp
// C++ API integration
class FGComMumbleAPI {
private:
    std::string api_base_url;
    std::string api_key;
    
public:
    void UpdatePlayerPosition(double lat, double lon, double alt);
    void UpdateRadioSettings(int channel, double freq, bool ptt);
    void GetAudioData(std::vector<float>& audio_buffer);
    void GetSignalQuality(double& quality, double& strength);
};
```

## Testing and Validation

### **1. Unit Testing**

**Test Requirements:**
- Position data accuracy
- Radio frequency validation
- Audio quality testing
- Network communication reliability

**Test Implementation:**
```cpp
// Example test framework
class FGComMumbleTests {
public:
    void TestPositionAccuracy();
    void TestRadioFrequencyValidation();
    void TestAudioQuality();
    void TestNetworkReliability();
    void TestIntegration();
};
```

### **2. Integration Testing**

**Test Scenarios:**
- Multiple players communication
- Long-distance communication
- Frequency interference
- Network disconnection/reconnection
- Performance under load

### **3. User Acceptance Testing**

**Test Cases:**
- Realistic radio communication
- Audio quality and effects
- User interface integration
- Performance impact on game

## Troubleshooting

### **Common Integration Issues**

**1. UDP Connection Problems**
- **Issue**: Cannot connect to FGCom-mumble server
- **Solution**: Check firewall settings, verify port 16661 is open
- **Debug**: Use `netstat -an | grep 16661` to verify port availability

**2. Audio Quality Issues**
- **Issue**: Poor audio quality or no audio
- **Solution**: Check audio device configuration, verify PTT functionality
- **Debug**: Monitor audio levels and signal quality

**3. Position Data Accuracy**
- **Issue**: Incorrect position data causing communication problems
- **Solution**: Verify coordinate system (WGS84), check altitude accuracy
- **Debug**: Compare with GPS coordinates

**4. Performance Impact**
- **Issue**: Game performance degradation
- **Solution**: Optimize update frequency, use threading
- **Debug**: Monitor CPU and memory usage

### **Debug Tools**

**1. Network Monitoring**
```bash
# Monitor UDP traffic
tcpdump -i any -n port 16661

# Test UDP connection
nc -u localhost 16661
```

**2. Audio Testing**
```bash
# Test audio output
aplay /dev/urandom

# Monitor audio devices
arecord -l
```

**3. Performance Monitoring**
```bash
# Monitor system resources
htop
iostat -x 1
```

## Best Practices

### **1. Performance Optimization**

- **Update Frequency**: Limit position updates to 10-20Hz
- **Threading**: Use separate threads for network communication
- **Memory Management**: Implement proper cleanup and resource management
- **Caching**: Cache frequently used data to reduce calculations

### **2. Error Handling**

- **Network Failures**: Implement automatic reconnection
- **Data Validation**: Validate all input data before transmission
- **Graceful Degradation**: Continue game operation if FGCom-mumble fails
- **Logging**: Implement comprehensive logging for debugging

### **3. User Experience**

- **Configuration**: Provide easy configuration options
- **Documentation**: Include clear setup instructions
- **Troubleshooting**: Provide common issue solutions
- **Support**: Offer technical support for integration issues

## Support and Resources

### **Documentation**
- [Technical Setup Guide](TECHNICAL_SETUP_GUIDE.md)
- [API Reference](API_REFERENCE_COMPLETE.md)
- [Amateur Radio Terminology](AMATEUR_RADIO_TERMINOLOGY.md)

### **Community Support**
- GitHub Issues: Report bugs and request features
- Documentation: Comprehensive technical guides
- Examples: Code samples and integration templates

### **Professional Support**
- For enterprise game development
- Custom integration assistance
- Training and consulting services

---

**Important Note**: Game integration with FGCom-mumble requires significant technical expertise and development time. This is not a simple "plug and play" integration. Developers should have experience with network programming, audio processing, and game engine architecture before attempting integration.
