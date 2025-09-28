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

#### **Network Optimization**
- Use batch updates when possible
- Implement connection pooling
- Handle network failures gracefully
- Use compression for large data sets

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
