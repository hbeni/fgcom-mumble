# FlightGear Lightning Data Investigation

## Overview

This document summarizes the investigation into what lightning and weather data FlightGear exposes through its property tree, and the format of that data.

## Sources

- [FlightGear Newsletter August 2015](https://wiki.flightgear.org/FlightGear_Newsletter_August_2015) - Lightning effects documentation
- [FlightGear Property Tree Documentation](https://wiki.flightgear.org/Property_tree) - General property tree structure
- [FlightGear Forum Discussions](https://forum.flightgear.org/viewtopic.php?f=69&p=336773&t=34755) - Weather system and METAR parsing

## Lightning Properties

### `/environment/lightning` Node

Based on the FlightGear Newsletter August 2015, the following properties are exposed:

#### Properties (Relative to Eye Position)
- **`lightning-pos-x`** - X position of lightning relative to current eye position
  - **Type**: Float (likely in meters or feet)
  - **Format**: Relative coordinate
  - **Note**: Not absolute latitude/longitude

- **`lightning-pos-y`** - Y position of lightning relative to current eye position
  - **Type**: Float (likely in meters or feet)
  - **Format**: Relative coordinate
  - **Note**: Not absolute latitude/longitude

- **`lightning-range`** - Range of lightning strike
  - **Type**: Float (likely in meters or kilometers)
  - **Format**: Distance value
  - **Note**: Distance from eye position to lightning strike

#### Additional Properties (Mentioned in Search Results)
- **`lightning-active`** - Whether lightning is currently active
  - **Type**: Boolean
  - **Format**: true/false or 1/0

- **`lightning-distance`** - Distance to nearest lightning strike
  - **Type**: Float
  - **Format**: Distance value

- **`lightning-count`** or **`strike-count`** - Number of lightning strikes
  - **Type**: Integer
  - **Format**: Count value

### `/environment/metar` Node

FlightGear processes METAR (Meteorological Aerodrome Report) data which includes weather phenomena:

- **METAR Data**: Contains parsed weather information including thunderstorm indicators
- **Thunderstorm Detection**: METAR parser identifies lightning/thunderstorm conditions
- **Format**: METAR string format (standard aviation weather format)

**Note**: METAR data is parsed by FlightGear's C++ code and properties are set accordingly. The Advanced Weather (AW) system accesses these parsed properties.

## Weather System Integration

### Advanced Weather System
- Lightning effects are generated during thunderstorms
- Visual lightning bolts are rendered
- Cloud illumination at night (within ALS framework)
- Thunder sounds are produced through the audio system
- Lightning can illuminate clouds up to 20 kilometers away

### METAR-Based Weather
- Weather conditions are determined from METAR data
- Thunderstorm/lightning conditions are parsed from METAR
- Properties are set based on METAR parsing results

## Data Format Considerations

### Coordinate System
**Important**: The `/environment/lightning` properties use **relative coordinates**, not absolute lat/lon:
- `lightning-pos-x` and `lightning-pos-y` are relative to the current eye position
- To get absolute coordinates, you would need to:
  1. Get aircraft position: `/position/latitude-deg`, `/position/longitude-deg`
  2. Calculate absolute lightning position from relative coordinates
  3. Account for heading and altitude

### Coordinate Conversion
To convert relative lightning coordinates to absolute lat/lon:
1. Get aircraft position:
   - `/position/latitude-deg` (degrees)
   - `/position/longitude-deg` (degrees)
   - `/position/altitude-ft` or `/position/altitude-agl-ft` (feet)

2. Get aircraft orientation (if needed):
   - `/orientation/heading-deg` (degrees)
   - `/orientation/pitch-deg` (degrees)
   - `/orientation/roll-deg` (degrees)

3. Calculate absolute position:
   - Convert relative X/Y to lat/lon offset
   - Apply offset to aircraft position
   - Account for Earth's curvature (for long distances)

## Current FlightGear Addon Status

The current `fgfs-addon` does **NOT** access any lightning/weather properties. It only accesses:
- Position: `/position/latitude-deg`, `/position/longitude-deg`, `/position/altitude-agl-ft`
- Radios: `/instrumentation/comm[n]/...`
- Callsign: `/sim/multiplay/callsign`

## Implementation Requirements

To implement lightning reporting from FlightGear to FGCom-mumble:

### 1. Property Tree Access
- Monitor `/environment/lightning` properties for changes
- Detect when lightning strikes occur (property value changes)
- Access aircraft position for coordinate conversion

### 2. Coordinate Conversion
- Convert relative `lightning-pos-x`/`lightning-pos-y` to absolute lat/lon
- Use aircraft position as reference point
- Calculate distance using `lightning-range`

### 3. UDP Packet Format

The UDP packet format used by FGCom-mumble is **ASCII-based** with the following specifications:

#### General Format
- **Encoding**: ASCII text
- **Field Format**: `Field=Value` pairs
- **Field Separator**: Comma (`,`)
- **Record Separator**: Newline (`\n`)
- **Maximum Packet Size**: 1024 bytes
- **Maximum Field Name Length**: 32 characters
- **Maximum Field Value Length**: 32 characters
- **Decimal Point**: Always use period (`.`) for floats, never comma
- **Empty Values**: `Field=` (empty value) is ignored
- **Field Order**: Not significant (fields can appear in any order)
- **Duplicate Fields**: Later occurrences overwrite earlier ones (unless value is empty)

#### Example Packet Format
```
LAT=48.123456,LON=11.654321,ALT=5000,CALLSIGN=TEST1,COM1_FRQ=121.5000,COM1_PTT=0,COM1_VOL=1.0
```

#### Current Supported Fields

**Position Data:**
- `LAT=12.345678` - Latitude in degrees (Float, 6+ decimal precision)
- `LON=12.345678` - Longitude in degrees (Float, 6+ decimal precision)
- `HGT=5000` - Altitude above ground level in feet (Float)
- `ALT=5000` - Altitude above sea level in feet (Int, legacy format)

**Identification:**
- `CALLSIGN=TEST1` - Callsign (String, arbitrary)

**Radio Data (per radio, n=1,2,3...):**
- `COM1_FRQ=121.5000` - Frequency in MHz (String/Float, minimum 4 decimals for real frequency)
- `COM1_VLT=12` - Electrical power, >0 means "has power" (Numeric)
- `COM1_PBT=1` - Power button: 0=off, 1=on (Bool)
- `COM1_SRV=1` - Serviceable: 0=failed, 1=operable (Bool)
- `COM1_PTT=1` - Push-to-talk: 0=off, 1=on (Bool)
- `COM1_VOL=1.0` - Volume: 0.0=mute, 1.0=full (Float)
- `COM1_PWR=10.0` - Transmitting power in watts (Float)
- `COM1_SQC=0.10` - Squelch: 0.0=off, 1.0=full (Float)
- `COM1_CWKHZ=8.33` - Channel width in kHz (Float)

**Configuration:**
- `AUDIO_FX_RADIO=1` - Radio audio effects: 0=off, 1=on (Bool)
- `AUDIO_HEAR_ALL=0` - Hear non-plugin users: 0=off, 1=on (Bool)
- `ALWAYSMUMBLEPTT=0` - Always handle Mumble PTT: 0=off, 1=on (Bool)
- `IID=0` - Identity ID (Int, for multiple identities)
- `UDP_TGT_PORT=19991` - UDP target port for RDF (Int)

#### Proposed Lightning Fields
To add lightning support, new fields would follow the same format:
- `LIGHTNING_LAT=48.123456` - Lightning strike latitude (Float, degrees)
- `LIGHTNING_LON=11.654321` - Lightning strike longitude (Float, degrees)
- `LIGHTNING_INTENSITY=25.5` - Strike intensity in kA (Float, if available)
- `LIGHTNING_RANGE=15.5` - Distance from aircraft in km (Float)
- `LIGHTNING_ALT=1000.0` - Strike altitude in meters (Float, if available)

#### Example Lightning Packet
```
LAT=48.123456,LON=11.654321,ALT=5000,CALLSIGN=TEST1,LIGHTNING_LAT=48.150000,LIGHTNING_LON=11.700000,LIGHTNING_INTENSITY=30.5,LIGHTNING_RANGE=12.3
```

#### Protocol Details
- **Port**: UDP port **16661** (default, compatible with original FGCom)
- **Fallback Ports**: If port 16661 is unavailable, plugin tries next 10 consecutive ports
- **Client Port**: Each UDP client port maps to an identity (IID)
- **Update Frequency**: Clients should send data regularly (e.g., every few seconds)
- **Packet Splitting**: For large packets, FlightGear protocol splits into multiple chunks (udp[0], udp[1], udp[2], udp[3])

#### Testing UDP Packets
You can test UDP packets manually using `netcat`:
```bash
echo "CALLSIGN=TEST1,COM1_FRQ=123.45,LAT=48.123456,LON=11.654321" | netcat -q0 -u localhost 16661 -p 50001
```

### 4. FlightGear Addon Enhancement
- Add Nasal script to monitor `/environment/lightning` properties
- Implement coordinate conversion logic
- Send UDP packets when lightning is detected
- Handle multiple strikes (if multiple properties exist)

## Verification Steps

To verify the exact property names and formats:

1. **Use FlightGear Property Browser**:
   - Launch FlightGear
   - Navigate to `Debug` > `Browse Internal Properties`
   - Explore `/environment/lightning` node
   - Check property names, types, and values during thunderstorms

2. **Test with Nasal Script**:
   ```nasal
   var lightning_node = props.globals.getNode("/environment/lightning", 1);
   var pos_x = lightning_node.getNode("lightning-pos-x");
   var pos_y = lightning_node.getNode("lightning-pos-y");
   var range = lightning_node.getNode("lightning-range");
   ```

3. **Monitor Property Changes**:
   - Set up listeners on lightning properties
   - Log values when they change
   - Verify coordinate system and units

## References

- [FlightGear Property Tree Documentation](https://wiki.flightgear.org/Property_tree)
- [FlightGear Newsletter August 2015 - Lightning Effects](https://wiki.flightgear.org/FlightGear_Newsletter_August_2015)
- [FlightGear Forum - Weather System Discussion](https://forum.flightgear.org/viewtopic.php?f=69&p=336773&t=34755)
- [FlightGear Generic Protocol](https://wiki.flightgear.org/Generic_Protocol) - For custom data exchange

## Notes

- Property names and structure may vary between FlightGear versions
- Some properties may only be available when Advanced Weather is enabled
- 3D clouds must be enabled to observe lightning effects
- METAR-based weather may have different property structures than Advanced Weather
- Coordinate conversion from relative to absolute requires careful calculation

## Next Steps

1. **Verify Property Names**: Use FlightGear Property Browser to confirm exact property paths
2. **Test Coordinate Conversion**: Develop and test conversion from relative to absolute coordinates
3. **Implement UDP Support**: Add lightning fields to UDP packet parser in `io_UDPServer.cpp`
4. **Add FlightGear Integration**: Enhance `fgfs-addon` to detect and report lightning strikes
5. **Test Integration**: Verify lightning data flows correctly from FlightGear to FGCom-mumble

