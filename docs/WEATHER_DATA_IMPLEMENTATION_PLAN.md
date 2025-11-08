# Weather Data Implementation Plan: FlightGear to FGCom-mumble

## Overview
This plan details the implementation of weather data (lightning, temperature, air pressure, humidity, rain) from FlightGear into the FGCom-mumble addon, which fetches data from FlightGear's property tree and creates UDP packets for the plugin.

## Current Constraints

### UDP Packet Limitations
- **FlightGear Protocol**: 4 UDP chunks (`udp[0]` through `udp[3]`)
- **Each Chunk**: ~256 characters (FlightGear generic protocol limit)
- **Total Packet**: MAXLINE = 1024 bytes
- **Field Length**: MAX_UDPSRV_FIELDLENGTH = 32 characters per field
- **Existing Multiplexing**: Radio data is already split across chunks

### Existing Structure
- Identity storage: `fgcom_client` struct in `globalVars.h`
- Multiplexing: Field-level distribution across 4 UDP chunks
- Update frequency: Position data sent frequently, other data less frequently

---

## Phase 1: Plugin-Side Data Structure

### 1.1 Add Weather Struct to Identity Storage
**File**: `client/mumble-plugin/lib/globalVars.h`

**Add weather structure:**
```cpp
struct fgcom_weather {
    float rain_intensity;        // 0.0-1.0
    float temperature_celsius;    // Temperature in Celsius
    float humidity_percent;        // 0.0-1.0 normalized, or 0-100%
    float pressure_hpa;           // Air pressure in hectopascals
    std::chrono::system_clock::time_point lastWeatherUpdate;
    
    // Lightning strikes (can have multiple)
    struct lightning_strike {
        double latitude;
        double longitude;
        float intensity_ka;        // Strike intensity in kiloamperes
        float range_km;           // Distance from aircraft in kilometers
        std::chrono::system_clock::time_point timestamp;
    };
    std::vector<lightning_strike> lightning_strikes;
    
    fgcom_weather() : rain_intensity(0.0f), temperature_celsius(20.0f),
                      humidity_percent(50.0f), pressure_hpa(1013.25f) {
        lastWeatherUpdate = std::chrono::system_clock::now();
    };
};
```

**Add to `fgcom_client` struct:**
```cpp
struct fgcom_client {
    mumble_userid_t mumid;
    uint16_t clientPort;
    uint16_t clientTgtPort;
    std::string clientHost;
    std::chrono::system_clock::time_point lastUpdate;
    std::chrono::system_clock::time_point lastNotification;
    float lon;
    float lat;
    float alt;
    std::string callsign;
    std::vector<fgcom_radio> radios;
    float lastSeenSignal;
    fgcom_weather weather;  // ADD THIS: Weather data per identity
    // ... constructor ...
};
```

---

## Phase 2: Multiplexing Strategy

### 2.1 Field-Level Multiplexing Design

**Priority Order (most critical first):**
1. **Position data** (LAT, LON, ALT) - Always in first chunk
2. **Callsign** - Always in first chunk
3. **Radio data** (COM1, COM2, etc.) - Split across chunks as needed
4. **Weather data** - Lower priority, can be in later chunks or omitted if space is tight
5. **Lightning data** - Event-driven, can use separate chunk (udp[3])

**Chunk Allocation Strategy:**
- **udp[0]**: Position + Callsign + COM1 (if fits) + Basic weather (if space)
- **udp[1]**: COM2, COM3, etc. + Weather data (if space)
- **udp[2]**: Additional radios + Extended weather
- **udp[3]**: Lightning data (sent less frequently, can use separate chunk)

### 2.2 Weather Data Update Frequency
- **Basic weather** (rain, temp, humidity, pressure): Every 2-5 seconds (less frequent than position)
- **Lightning strikes**: Event-driven (immediately when detected)
- **Lightning cleanup**: Remove old strikes (>5 minutes old)

### 2.3 Field-Level Splitting Algorithm
**File**: `client/fgfs-addon/addon-main.nas`

**Enhancement to `update_udp_output()`:**
- Split at field level, not just radio level
- Weather fields can be split across chunks if needed
- Example: `RAIN_INTENSITY=0.75` can go in one chunk, `TEMPERATURE=18.5` in another

**Algorithm:**
1. Build field list: [position fields, callsign, radio fields, weather fields, lightning fields]
2. Distribute fields across chunks, respecting 256-char limit per chunk
3. Ensure critical fields (LAT, LON, CALLSIGN) always in first chunk
4. Weather fields can be distributed across multiple chunks if needed

---

## Phase 3: FlightGear Addon Implementation

### 3.1 Weather Module Structure
**File**: `client/fgfs-addon/weather.nas` (new file)

**Key Functions:**
```nasal
var FGComMumble_weather = {
    // Weather data cache
    weather_data: {
        rain_intensity: 0.0,
        temperature: 20.0,
        humidity: 0.5,
        pressure: 1013.25,
        last_update: 0
    },
    
    // Lightning strike cache
    lightning_strikes: [],
    last_lightning_check: 0,
    
    // Property nodes (cached for performance)
    rain_node: nil,
    temp_node: nil,
    humidity_node: nil,
    pressure_node: nil,
    lightning_x_node: nil,
    lightning_y_node: nil,
    lightning_range_node: nil,
    aircraft_lat_node: nil,
    aircraft_lon_node: nil,
    aircraft_heading_node: nil,
    
    // Initialize property nodes
    init: func() {
        me.rain_node = props.globals.getNode("/environment/rain-norm", 1);
        me.temp_node = props.globals.getNode("/environment/metar/temperature-degc", 1);
        me.humidity_node = props.globals.getNode("/environment/metar/rel-humidity-norm", 1);
        me.pressure_node = props.globals.getNode("/environment/pressure-inhg", 1);
        me.lightning_x_node = props.globals.getNode("/environment/lightning/lightning-pos-x", 1);
        me.lightning_y_node = props.globals.getNode("/environment/lightning/lightning-pos-y", 1);
        me.lightning_range_node = props.globals.getNode("/environment/lightning/lightning-range", 1);
        me.aircraft_lat_node = props.globals.getNode("/position/latitude-deg", 1);
        me.aircraft_lon_node = props.globals.getNode("/position/longitude-deg", 1);
        me.aircraft_heading_node = props.globals.getNode("/orientation/heading-deg", 1);
    },
    
    // Update weather data from FlightGear properties
    updateWeatherData: func() {
        var now = systime();
        if (now - me.weather_data.last_update < 2.0) {
            return;  // Don't update more than once every 2 seconds
        }
        
        if (me.rain_node != nil) {
            me.weather_data.rain_intensity = me.rain_node.getValue();
        }
        if (me.temp_node != nil) {
            me.weather_data.temperature = me.temp_node.getValue();
        }
        if (me.humidity_node != nil) {
            var hum = me.humidity_node.getValue();
            me.weather_data.humidity = hum;  // Already normalized 0.0-1.0
        }
        if (me.pressure_node != nil) {
            var pressure_inhg = me.pressure_node.getValue();
            me.weather_data.pressure = pressure_inhg * 33.8639;  // Convert inHg to hPa
        }
        me.weather_data.last_update = now;
    },
    
    // Detect and convert lightning strikes
    updateLightningData: func() {
        if (me.lightning_x_node == nil or me.lightning_y_node == nil) {
            return;
        }
        
        var lightning_x = me.lightning_x_node.getValue();
        var lightning_y = me.lightning_y_node.getValue();
        var lightning_range = 0.0;
        if (me.lightning_range_node != nil) {
            lightning_range = me.lightning_range_node.getValue();
        }
        
        // Check if lightning is active (non-zero values)
        if (lightning_x != 0.0 or lightning_y != 0.0) {
            // Convert relative coordinates to absolute lat/lon
            var aircraft_lat = me.aircraft_lat_node.getValue();
            var aircraft_lon = me.aircraft_lon_node.getValue();
            var aircraft_heading = 0.0;
            if (me.aircraft_heading_node != nil) {
                aircraft_heading = me.aircraft_heading_node.getValue();
            }
            
            // Convert relative X/Y (meters) to lat/lon offset
            // Simple approximation: 1 degree lat ≈ 111 km, 1 degree lon ≈ 111 km * cos(lat)
            var lat_offset = lightning_y / 111000.0;  // Convert meters to degrees
            var lon_offset = lightning_x / (111000.0 * math.cos(math.rad(aircraft_lat)));
            
            // Apply heading rotation if needed (simplified - may need more complex calculation)
            var abs_lat = aircraft_lat + lat_offset;
            var abs_lon = aircraft_lon + lon_offset;
            
            // Add to lightning strikes array
            var strike = {
                latitude: abs_lat,
                longitude: abs_lon,
                intensity: 25.0,  // Default if not available
                range: lightning_range / 1000.0,  // Convert to km
                timestamp: systime()
            };
            append(me.lightning_strikes, strike);
            
            // Clean old strikes (>5 minutes)
            var cutoff_time = systime() - 300.0;
            var filtered_strikes = [];
            foreach (var s; me.lightning_strikes) {
                if (s.timestamp > cutoff_time) {
                    append(filtered_strikes, s);
                }
            }
            me.lightning_strikes = filtered_strikes;
        }
    },
    
    // Generate UDP weather string
    getWeatherUDPString: func() {
        me.updateWeatherData();
        var fields = [];
        
        if (me.weather_data.rain_intensity > 0.0) {
            append(fields, "RAIN_INTENSITY=" ~ sprintf("%.2f", me.weather_data.rain_intensity));
        }
        if (me.weather_data.temperature != 20.0) {  // Only send if not default
            append(fields, "TEMPERATURE=" ~ sprintf("%.1f", me.weather_data.temperature));
        }
        if (me.weather_data.humidity != 0.5) {  // Only send if not default
            append(fields, "HUMIDITY=" ~ sprintf("%.2f", me.weather_data.humidity));
        }
        if (me.weather_data.pressure != 1013.25) {  // Only send if not default
            append(fields, "PRESSURE=" ~ sprintf("%.2f", me.weather_data.pressure));
        }
        
        return string.join(",", fields);
    },
    
    // Generate UDP lightning string (most recent strike only)
    getLightningUDPString: func() {
        me.updateLightningData();
        
        if (size(me.lightning_strikes) == 0) {
            return "";
        }
        
        // Get most recent strike
        var latest_strike = me.lightning_strikes[size(me.lightning_strikes) - 1];
        var fields = [];
        
        append(fields, "LIGHTNING_LAT=" ~ sprintf("%.6f", latest_strike.latitude));
        append(fields, "LIGHTNING_LON=" ~ sprintf("%.6f", latest_strike.longitude));
        append(fields, "LIGHTNING_INTENSITY=" ~ sprintf("%.1f", latest_strike.intensity));
        append(fields, "LIGHTNING_RANGE=" ~ sprintf("%.1f", latest_strike.range));
        
        return string.join(",", fields);
    }
};
```

### 3.2 Coordinate Conversion for Lightning
**Function**: Convert relative `lightning-pos-x/y` to absolute lat/lon

**Algorithm:**
1. Get aircraft position: `/position/latitude-deg`, `/position/longitude-deg`
2. Get aircraft heading: `/orientation/heading-deg` (if needed for rotation)
3. Convert relative X/Y (meters) to lat/lon offset:
   - 1 degree latitude ≈ 111,000 meters
   - 1 degree longitude ≈ 111,000 * cos(latitude) meters
4. Apply offset to aircraft position
5. Account for Earth's curvature for long distances (if needed)

**Note**: This is a simplified conversion. For more accuracy, may need to account for:
- Heading rotation
- Earth's curvature
- Altitude differences

### 3.3 Integration with Existing Multiplexing
**File**: `client/fgfs-addon/addon-main.nas`

**Modify `update_udp_output()` function:**
- Add weather fields to field list
- Distribute weather fields across available chunks
- Prioritize: Position > Callsign > Radios > Weather > Lightning

**Field List Building:**
```nasal
var update_udp_output = func() {
    FGComMumble.logger.log("udp", 3, "  updating final UDP transmit field...");
    
    // Build complete field list
    var all_fields = [];
    
    // 1. Position fields (always first, always in udp[0])
    var lat = getprop("/position/latitude-deg");
    var lon = getprop("/position/longitude-deg");
    var alt = getprop("/position/altitude-agl-ft");
    append(all_fields, "LAT=" ~ sprintf("%.6f", lat));
    append(all_fields, "LON=" ~ sprintf("%.6f", lon));
    append(all_fields, "ALT=" ~ sprintf("%.0f", alt));
    
    // 2. Callsign (always in udp[0])
    var callsign = getprop("/sim/multiplay/callsign");
    if (callsign != nil) {
        append(all_fields, "CALLSIGN=" ~ callsign);
    }
    
    // 3. Radio fields (from existing code)
    foreach (r_out; FGComMumble.rootNodeOutput.getChildren("COM")) {
        var radio_str = r_out.getValue();
        if (size(radio_str) > 0) {
            var radio_fields = split(",", radio_str);
            foreach (rf; radio_fields) {
                if (size(rf) > 0) {
                    append(all_fields, rf);
                }
            }
        }
    }
    
    // 4. Weather fields (lower priority)
    var weather_str = FGComMumble_weather.getWeatherUDPString();
    if (size(weather_str) > 0) {
        var weather_fields = split(",", weather_str);
        foreach (wf; weather_fields) {
            if (size(wf) > 0) {
                append(all_fields, wf);
            }
        }
    }
    
    // 5. Lightning fields (event-driven, can be in separate chunk)
    var lightning_str = FGComMumble_weather.getLightningUDPString();
    if (size(lightning_str) > 0) {
        var lightning_fields = split(",", lightning_str);
        foreach (lf; lightning_fields) {
            if (size(lf) > 0) {
                append(all_fields, lf);
            }
        }
    }
    
    // Distribute fields across chunks (field-level splitting)
    var out_prop = [
        props.globals.getNode(mySettingsRootPath ~ "/output/udp[0]", 1),
        props.globals.getNode(mySettingsRootPath ~ "/output/udp[1]", 1),
        props.globals.getNode(mySettingsRootPath ~ "/output/udp[2]", 1),
        props.globals.getNode(mySettingsRootPath ~ "/output/udp[3]", 1)
    ];
    
    var udpout_idx = 0;
    var udpout_chars = 0;
    var str_v = [];
    
    foreach (field; all_fields) {
        var field_size = size(field) + 1;  // +1 for comma separator
        
        if (udpout_chars + field_size < 256) {
            append(str_v, field);
            udpout_chars = udpout_chars + field_size;
        } else {
            // Overflow: finish current chunk and move to next
            if (size(str_v) > 0) {
                out_prop[udpout_idx].setValue(string.join(",", str_v));
            }
            str_v = [];
            udpout_idx = udpout_idx + 1;
            udpout_chars = 0;
            
            if (udpout_idx < 4) {
                append(str_v, field);
                udpout_chars = field_size;
            } else {
                // All chunks full, skip remaining fields
                FGComMumble.logger.log("udp", 1, "WARNING: UDP packet overflow, some fields dropped");
                break;
            }
        }
    }
    
    // Store remaining fields in current chunk
    if (size(str_v) > 0 and udpout_idx < 4) {
        out_prop[udpout_idx].setValue(string.join(",", str_v));
    }
    
    // Clean remaining unused chunks
    for (var i = udpout_idx + 1; i < 4; i = i + 1) {
        out_prop[i].setValue("");
    }
};
```

**Integration into main addon:**
```nasal
# In main() function, after loading radios:
io.load_nasal(root~"/weather.nas", "FGComMumble_weather");
FGComMumble_weather.FGComMumble = FGComMumble;
FGComMumble_weather.init();
```

---

## Phase 4: Plugin-Side UDP Parser

### 4.1 Parse Weather Fields
**File**: `client/mumble-plugin/lib/io_UDPServer.cpp`

**Add parsing in `fgcom_udp_parseMsg()` function (around line 426-540):**

```cpp
// Temporary storage for lightning data (until all fields received)
static std::map<int, double> lightning_temp_lat;
static std::map<int, double> lightning_temp_lon;

// In the token parsing loop, add:

// Weather fields
if (token_key == "RAIN_INTENSITY") {
    fgcom_local_client[iid].weather.rain_intensity = std::stof(token_value);
    fgcom_local_client[iid].weather.lastWeatherUpdate = std::chrono::system_clock::now();
}
if (token_key == "TEMPERATURE") {
    fgcom_local_client[iid].weather.temperature_celsius = std::stof(token_value);
    fgcom_local_client[iid].weather.lastWeatherUpdate = std::chrono::system_clock::now();
}
if (token_key == "HUMIDITY") {
    float hum = std::stof(token_value);
    // If normalized (0.0-1.0), convert to percent
    if (hum <= 1.0) hum *= 100.0;
    fgcom_local_client[iid].weather.humidity_percent = hum;
    fgcom_local_client[iid].weather.lastWeatherUpdate = std::chrono::system_clock::now();
}
if (token_key == "PRESSURE") {
    fgcom_local_client[iid].weather.pressure_hpa = std::stof(token_value);
    fgcom_local_client[iid].weather.lastWeatherUpdate = std::chrono::system_clock::now();
}

// Lightning fields
if (token_key == "LIGHTNING_LAT") {
    // Store temporarily, will create strike when LON is received
    lightning_temp_lat[iid] = std::stod(token_value);
}
if (token_key == "LIGHTNING_LON") {
    // Create lightning strike
    fgcom_weather::lightning_strike strike;
    strike.latitude = lightning_temp_lat[iid];
    strike.longitude = std::stod(token_value);
    strike.timestamp = std::chrono::system_clock::now();
    strike.intensity_ka = 25.0;  // Default if not provided
    strike.range_km = 0.0;  // Default if not provided
    fgcom_local_client[iid].weather.lightning_strikes.push_back(strike);
    
    // Clean up temp storage
    lightning_temp_lat.erase(iid);
    lightning_temp_lon.erase(iid);
}
if (token_key == "LIGHTNING_INTENSITY") {
    if (!fgcom_local_client[iid].weather.lightning_strikes.empty()) {
        fgcom_local_client[iid].weather.lightning_strikes.back().intensity_ka = std::stof(token_value);
    }
}
if (token_key == "LIGHTNING_RANGE") {
    if (!fgcom_local_client[iid].weather.lightning_strikes.empty()) {
        fgcom_local_client[iid].weather.lightning_strikes.back().range_km = std::stof(token_value);
    }
}
```

### 4.2 Cleanup Old Lightning Strikes
**File**: `client/mumble-plugin/lib/io_UDPServer.cpp` or `fgcom-mumble.cpp`

**Add periodic cleanup:**
```cpp
// Clean old lightning strikes (>5 minutes old)
void cleanupOldLightningStrikes() {
    auto cutoff_time = std::chrono::system_clock::now() - std::chrono::minutes(5);
    
    for (auto& client_pair : fgcom_local_client) {
        auto& strikes = client_pair.second.weather.lightning_strikes;
        strikes.erase(
            std::remove_if(strikes.begin(), strikes.end(),
                [cutoff_time](const fgcom_weather::lightning_strike& strike) {
                    return strike.timestamp < cutoff_time;
                }),
            strikes.end()
        );
    }
}
```

---

## Phase 5: Integration with Noise Calculation System

### 5.1 Update Weather Conditions
**File**: `client/mumble-plugin/lib/io_UDPServer.cpp` or `fgcom-mumble.cpp`

**When weather data is received, update atmospheric noise system:**

```cpp
// After parsing weather fields, update noise system
void updateAtmosphericNoiseFromWeather(int iid) {
    if (fgcom_local_client.count(iid) == 0) return;
    
    auto& client_weather = fgcom_local_client[iid].weather;
    
    // Convert fgcom_weather to NoiseWeatherConditions
    FGCom_AtmosphericNoise::NoiseWeatherConditions weather;
    weather.has_precipitation = (client_weather.rain_intensity > 0.0);
    weather.temperature_celsius = client_weather.temperature_celsius;
    weather.humidity_percent = client_weather.humidity_percent;
    weather.has_thunderstorms = !client_weather.lightning_strikes.empty();
    
    // Calculate storm intensity from lightning strikes
    if (!client_weather.lightning_strikes.empty()) {
        float total_intensity = 0.0;
        for (const auto& strike : client_weather.lightning_strikes) {
            total_intensity += strike.intensity_ka;
        }
        weather.storm_intensity = total_intensity / client_weather.lightning_strikes.size();
        
        // Calculate average distance
        float total_range = 0.0;
        for (const auto& strike : client_weather.lightning_strikes) {
            total_range += strike.range_km;
        }
        weather.storm_distance_km = total_range / client_weather.lightning_strikes.size();
    }
    
    // Update atmospheric noise system
    FGCom_AtmosphericNoise::getInstance().setWeatherConditions(weather);
    
    // Process lightning strikes
    for (const auto& strike : client_weather.lightning_strikes) {
        FGCom_AtmosphericNoise::LightningStrike ls;
        ls.latitude = strike.latitude;
        ls.longitude = strike.longitude;
        ls.intensity = strike.intensity_ka;
        ls.timestamp = std::chrono::system_clock::to_time_t(strike.timestamp);
        FGCom_AtmosphericNoise::getInstance().addLightningStrike(ls);
    }
}
```

**Call this function after parsing weather fields:**
```cpp
// After parsing weather/lightning fields:
if (weather_data_received) {
    updateAtmosphericNoiseFromWeather(iid);
}
```

---

## Phase 6: Multiplexing Optimization

### 6.1 Field-Level Distribution Algorithm
**Strategy:**
- Calculate field sizes before distribution
- Fill chunks to maximize space usage
- Critical fields (LAT, LON, CALLSIGN) always in first chunk
- Weather can be split: `RAIN_INTENSITY` in one chunk, `TEMPERATURE` in another
- Lightning can use `udp[3]` if other chunks are full

**Field Size Calculation:**
- `LAT=48.123456` = 16 chars
- `RAIN_INTENSITY=0.75` = 20 chars
- `TEMPERATURE=18.5` = 15 chars
- `LIGHTNING_LAT=48.150000` = 22 chars

**Example Distribution:**
- **udp[0]**: LAT, LON, ALT, CALLSIGN, COM1_FRQ, COM1_PTT, COM1_VOL (fits ~200 chars)
- **udp[1]**: COM2_FRQ, COM2_PTT, RAIN_INTENSITY, TEMPERATURE (fits ~200 chars)
- **udp[2]**: COM3_FRQ, HUMIDITY, PRESSURE (fits ~150 chars)
- **udp[3]**: LIGHTNING_LAT, LIGHTNING_LON, LIGHTNING_INTENSITY, LIGHTNING_RANGE (fits ~100 chars)

### 6.2 Update Frequency Optimization
- **Position**: Every update (1-10 Hz) - Always sent
- **Weather**: Every 2-5 seconds - Only sent if changed or time threshold exceeded
- **Lightning**: Event-driven - Only sent when new strike detected
- **Lightning cleanup**: Remove old strikes (>5 minutes old) to prevent array growth

### 6.3 Conditional Field Sending
**Optimization**: Only send weather fields if they differ from defaults:
- `RAIN_INTENSITY`: Only if > 0.0
- `TEMPERATURE`: Only if != 20.0 (default)
- `HUMIDITY`: Only if != 0.5 (default)
- `PRESSURE`: Only if != 1013.25 (default)

This reduces packet size when weather is normal.

---

## Phase 7: Testing Plan

### 7.1 Unit Testing
- Test coordinate conversion (relative to absolute)
- Test value range validation
- Test UDP packet format generation
- Test field-level splitting algorithm

### 7.2 Integration Testing
- Test with FlightGear running
- Verify properties are read correctly
- Verify UDP packets are sent correctly
- Verify plugin receives and parses data
- Verify multiplexing works correctly (fields distributed across chunks)

### 7.3 Functional Testing
- Test with actual thunderstorms in FlightGear
- Test with rain enabled
- Test with various weather conditions
- Verify noise floor changes with weather
- Test multiple clients sending weather data
- Test packet overflow handling (when all chunks full)

### 7.4 Performance Testing
- Test update frequency impact
- Test memory usage (lightning strike array growth)
- Test CPU usage with frequent weather updates

---

## Phase 8: Implementation Order

1. **Phase 1**: Add weather struct to `fgcom_client` in `globalVars.h`
2. **Phase 3**: Create weather module in FlightGear addon (`weather.nas`)
3. **Phase 3.3**: Integrate weather module into main addon and update multiplexing
4. **Phase 4**: Add UDP field parsing in plugin (`io_UDPServer.cpp`)
5. **Phase 5**: Integrate with noise calculation system
6. **Phase 6**: Optimize multiplexing and update frequency
7. **Phase 7**: Testing and validation
8. **Documentation**: Update plugin.spec.md with new UDP fields

---

## Key Design Decisions

1. **Weather struct in `fgcom_client`**: Stores weather per identity, allowing multiple clients with different weather
2. **Field-level multiplexing**: Split individual fields, not just radio blocks, for better space utilization
3. **Priority system**: Position > Callsign > Radios > Weather > Lightning
4. **Update frequency**: Weather less frequent than position (2-5 seconds vs 1-10 Hz)
5. **Lightning handling**: Event-driven, can use separate chunk (udp[3])
6. **Backward compatibility**: Clients without weather data still work (missing fields ignored)
7. **Conditional sending**: Only send weather fields if they differ from defaults
8. **Lightning cleanup**: Remove old strikes to prevent memory growth

---

## Notes

- **Coordinate conversion**: Lightning uses relative coordinates; conversion needed to absolute lat/lon
- **Property availability**: Some properties may not exist in all FlightGear versions/configurations
- **Error handling**: Gracefully handle missing properties (use defaults)
- **Packet size**: Monitor total packet size to stay under 1024 bytes
- **Field length**: Ensure all field names and values stay under 32 characters
- **Testing**: Test with various FlightGear weather configurations (Basic Weather vs Advanced Weather)

---

## Investigation Results: Multiple Lightning Strikes and Precipitation Types

### Multiple Lightning Strikes

**FlightGear Capability:**
- FlightGear simulates multiple lightning strikes during thunderstorms
- The ALS framework tracks all thunderstorms within the field of view
- Generates varying patterns of lightning strikes with different frequencies

**Property Tree Exposure:**
- `/environment/lightning/lightning-pos-x` - Single X position (relative to eye)
- `/environment/lightning/lightning-pos-y` - Single Y position (relative to eye)
- `/environment/lightning/lightning-range` - Single range value

**Finding:**
- FlightGear renders multiple strikes visually, but the property tree only exposes **one lightning position at a time**
- The system tracks multiple strikes internally, but property tree access is limited to current/nearest strike
- No documented array or list structure for multiple strikes (e.g., `/environment/lightning[0]`, `/environment/lightning[1]`)

**Conclusion:**
- Multiple strikes are simulated but not exposed as an array in property tree
- **Workaround Required**: Track strikes in addon by monitoring property changes over time
- Send strikes sequentially or batch them in the addon

**Implementation Approach:**
1. Monitor `/environment/lightning` properties for changes
2. When values change, record as a new strike in addon's lightning_strikes array
3. Track strikes with timestamps
4. Send strikes sequentially or batch them in UDP packets
5. Clean up old strikes (>5 minutes old)

**UDP Packet Strategy:**
- Option 1: Send most recent strike in each packet (simplest)
- Option 2: Send multiple strikes in separate packets if space allows
- Option 3: Batch multiple strikes: `LIGHTNING_LAT1=...,LIGHTNING_LON1=...,LIGHTNING_LAT2=...,LIGHTNING_LON2=...` (if field length allows)

---

### Precipitation Types (Snow, Hail, Sleet)

**FlightGear Capability:**
- FlightGear supports rain, snow, and hail rendering
- Precipitation system has been upgraded to render different types with distinct visual properties
- Each type has different visual characteristics (droplet size, streak patterns, etc.)

**Property Tree Exposure:**
- `/environment/rain-norm` - Rain intensity (0.0-1.0) - **Confirmed**
- `/environment/precipitation/` - Precipitation node (mentioned but not detailed)
- `/environment/precipitation/rate` - Precipitation rate (mentioned in search results)
- METAR data may contain precipitation type codes

**Finding:**
- Specific property paths for precipitation **type** (snow/hail/sleet) are **not clearly documented**
- Graphics card profiles mention precipitation parameters but not type selection
- METAR parsing may include precipitation type, but specific property paths are unclear

**Conclusion:**
- Precipitation types are rendered visually, but explicit type properties are not clearly documented
- **May require:**
  - Parsing METAR strings for type codes (SN = snow, GR = hail, etc.)
  - Using temperature + precipitation to infer type (temperature < 0°C = snow)
  - Checking if `/environment/precipitation/type` exists (needs verification in FlightGear Property Browser)

**Implementation Approach:**
1. **Verify in FlightGear Property Browser:**
   - Check if `/environment/precipitation/type` exists
   - Check `/environment/metar/` for precipitation type properties
   - Check weather dialog settings for type selection properties

2. **If property exists:**
   - Read directly: `PRECIPITATION_TYPE=rain|snow|hail|none`

3. **If property doesn't exist:**
   - **Option A**: Infer from temperature:
     - If temperature < 0°C and precipitation > 0 → snow
     - If temperature > 0°C and precipitation > 0 → rain
     - Hail detection may require METAR parsing
   - **Option B**: Parse METAR string for weather phenomena codes:
     - `RA` = Rain
     - `SN` = Snow
     - `GR` = Hail
     - `PL` = Ice pellets
     - `SG` = Snow grains

**UDP Packet Field:**
- `PRECIPITATION_TYPE=rain` (String format)
- Or numeric: `PRECIPITATION_TYPE=0` (none), `1` (rain), `2` (snow), `3` (hail), `4` (sleet)

---

### Verification Steps

To confirm these findings, use FlightGear Property Browser:

1. **Multiple Lightning Strikes:**
   - Launch FlightGear with thunderstorms enabled
   - Navigate to `Debug` > `Browse Internal Properties`
   - Check if `/environment/lightning[0]`, `/environment/lightning[1]` exist (array notation)
   - Monitor property changes during active thunderstorms
   - Check if multiple positions are exposed simultaneously

2. **Precipitation Types:**
   - Launch FlightGear with snow/hail enabled
   - Navigate to `Debug` > `Browse Internal Properties`
   - Check for `/environment/precipitation/type`
   - Check `/environment/metar/` for precipitation type properties
   - Check weather dialog settings for type selection properties
   - Verify METAR parsing includes type codes

---

## Possible Future Enhancements

- More accurate coordinate conversion (account for heading, Earth's curvature) - **Feasible** (heading data available)
- Support for multiple lightning strikes in single packet - **Feasible with workaround** (track in addon)
- Weather data interpolation between updates - **Feasible** (implementation feature)
- Support for snow, hail, and other precipitation types - **Feasible with workaround** (infer from temperature or parse METAR)
- Weather data validation and range checking - **Feasible** (implementation feature)

