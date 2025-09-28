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
