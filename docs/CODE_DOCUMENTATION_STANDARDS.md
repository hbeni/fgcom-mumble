# Code Documentation Standards: No Claims, Just Facts

## Universal Principle

**ALL code must be self-documenting with clear comments, but NO claims!**

Every line of code must explain:
- **What** it does (factual)
- **Why** it does it (factual)
- **What happens** if it's wrong (factual)
- **Examples** of correct usage (factual)

## The Standards

### 1. **External Tool Interfaces**
**Every line that handles file formats, protocols, or external tool interfaces MUST have comments explaining:**

```python
# CRITICAL: NEC2 GW format is exactly: GW tag# segments# x1 y1 z1 x2 y2 z2 radius
# Do NOT add extra fields or the coordinate parsing will be shifted!
# This format is position-sensitive - any deviation breaks NEC2 geometry parsing
parts = line.split()
if len(parts) >= 9:  # Must have exactly 9 fields (GW + 8 parameters)
    tag = int(parts[1])        # Wire tag number
    segments = int(parts[2])   # Number of segments
    x1 = float(parts[3])       # Start point X coordinate
    y1 = float(parts[4])       # Start point Y coordinate  
    z1 = float(parts[5])       # Start point Z coordinate
    x2 = float(parts[6])      # End point X coordinate
    y2 = float(parts[7])      # End point Y coordinate
    z2 = float(parts[8])      # End point Z coordinate
    radius = float(parts[9])  # Wire radius
```

### 2. **Mathematical Operations**
**Every mathematical operation MUST have comments explaining:**

```python
# Apply transformations in order: altitude → pitch → roll
# This matches aircraft attitude conventions (pitch then roll)
# Apply pitch rotation (rotation around Y axis)
# This rotates the antenna up/down (nose up/down)
new_x1 = x1 * cos_pitch + z1_alt * sin_pitch
new_z1_temp = -x1 * sin_pitch + z1_alt * cos_pitch

# Apply roll rotation (rotation around X axis)
# This rotates the antenna left/right (wing up/down)
new_y1 = y1 * cos_roll - new_z1_temp * sin_roll
new_z1 = y1 * sin_roll + new_z1_temp * cos_roll
```

### 3. **Output Formats**
**Every output statement MUST have comments explaining:**

```python
# OUTPUT: GW tag segments x1 y1 z1 x2 y2 z2 radius (9 fields exactly)
# Any deviation breaks NEC2 geometry parsing!
print(f'GW {tag} {segments} {new_x1:.6f} {new_y1:.6f} {new_z1:.6f} {new_x2:.6f} {new_y2:.6f} {new_z2:.6f} {radius:.6f}')
```

### 4. **Network Communication**
**Every network operation MUST have comments explaining:**

```cpp
// Rate throttling: Check if we should throttle this notification
// Minimum 100ms between notifications to prevent message flooding
static std::map<std::string, std::chrono::steady_clock::time_point> last_notification_time;
static const std::chrono::milliseconds min_interval(100);

std::string throttle_key = std::to_string(iid) + "_" + std::to_string(what);
auto now = std::chrono::steady_clock::now();

if (last_notification_time.find(throttle_key) != last_notification_time.end()) {
    auto time_since_last = now - last_notification_time[throttle_key];
    if (time_since_last < min_interval) {
        // Skip notification to prevent rate limiting
        return;
    }
}
```

### 5. **Audio Processing**
**Every audio operation MUST have comments explaining:**

```cpp
// Apply signal quality degradation for poor signal conditions
// This simulates real-world radio behavior where poor signal quality
// causes audio dropouts and distortion
if (signalVolume < 0.3) {  // Poor signal threshold
    float dropoutProbability = (0.3 - signalVolume) * 0.5;  // 0-15% dropout rate
    fgcom_audio_applySignalQualityDegradation(outputPCM, sampleCount, channelCount, dropoutProbability);
}
```

### 6. **Radio Models**
**Every radio operation MUST have comments explaining:**

```cpp
// UHF radio parameters based on aviation/military standards
// Standard UHF channel spacing: 25kHz (military), 12.5kHz (civilian), 6.25kHz (narrowband)
float width_kHz = r1.channelWidth;
if (width_kHz <= 0) width_kHz = 25.0;  // Standard 25kHz channel spacing for UHF
float channel_core = width_kHz / 2.0;   // Channel core is half the channel width
```

### 7. **HTTP Operations**
**Every HTTP operation MUST have comments explaining:**

```cpp
// Properly parse Accept-Encoding header with quality values
// Look for "br" with optional quality value (e.g., "br", "br;q=0.8", "br;q=1.0")
if (s.find("br") != std::string::npos) {
    // Check if br has quality value and if it's acceptable (> 0)
    size_t br_pos = s.find("br");
    if (br_pos != std::string::npos) {
        size_t q_pos = s.find("q=", br_pos);
        if (q_pos != std::string::npos && q_pos < s.find(",", br_pos)) {
            // Parse quality value
            std::string q_str = s.substr(q_pos + 2);
            size_t end_pos = q_str.find_first_of(",;");
            if (end_pos != std::string::npos) q_str = q_str.substr(0, end_pos);
            
            try {
                double q_value = std::stod(q_str);
                if (q_value > 0.0) return EncodingType::Brotli;
            } catch (...) {
                // If parsing fails, assume q=1.0
                return EncodingType::Brotli;
            }
        } else {
            // No quality value specified, assume q=1.0
            return EncodingType::Brotli;
        }
    }
}
```

### 8. **File Operations**
**Every file operation MUST have comments explaining:**

```cpp
// Implement HTTP download using system wget/curl command
// This provides a robust download mechanism without requiring CURL library
std::string command;
std::string temp_file = filepath + ".tmp";

// Try wget first, then curl as fallback
command = "wget --timeout=30 --tries=3 --user-agent='FGCom-mumble/1.0' -O '" + temp_file + "' '" + url + "' 2>/dev/null";
int result = system(command.c_str());

if (result != 0) {
    // Try curl as fallback
    command = "curl --connect-timeout 30 --max-time 300 --user-agent 'FGCom-mumble/1.0' -o '" + temp_file + "' '" + url + "' 2>/dev/null";
    result = system(command.c_str());
}
```

## The Rules

### Rule 1: Document Every External Interface
- File formats
- Network protocols
- API calls
- Database schemas
- Command-line tools
- Configuration files

### Rule 2: Document Every Mathematical Operation
- Coordinate transformations
- Signal processing
- Statistical calculations
- Algorithm steps
- Formula implementations
- Numerical methods

### Rule 3: Document Every Output Format
- File generation
- Network messages
- Log entries
- Error messages
- Status updates
- Data structures

### Rule 4: Document Every Input Validation
- Parameter checking
- Range validation
- Type conversion
- Error handling
- Boundary conditions
- Edge cases

### Rule 5: Document Every State Change
- Variable assignments
- Object modifications
- State transitions
- Side effects
- Dependencies
- Assumptions

## Examples of Good Documentation

### Example 1: File Format Parsing
```python
# CRITICAL: NEC2 GW format is exactly: GW tag# segments# x1 y1 z1 x2 y2 z2 radius
# Do NOT add extra fields or the coordinate parsing will be shifted!
# This format is position-sensitive - any deviation breaks NEC2 geometry parsing
parts = line.split()
if len(parts) >= 9:  # Must have exactly 9 fields (GW + 8 parameters)
    tag = int(parts[1])        # Wire tag number
    segments = int(parts[2])   # Number of segments
    x1 = float(parts[3])       # Start point X coordinate
    y1 = float(parts[4])       # Start point Y coordinate  
    z1 = float(parts[5])       # Start point Z coordinate
    x2 = float(parts[6])      # End point X coordinate
    y2 = float(parts[7])      # End point Y coordinate
    z2 = float(parts[8])      # End point Z coordinate
    radius = float(parts[9])  # Wire radius
```

### Example 2: Network Communication
```cpp
// Rate throttling: Check if we should throttle this notification
// Minimum 100ms between notifications to prevent message flooding
static std::map<std::string, std::chrono::steady_clock::time_point> last_notification_time;
static const std::chrono::milliseconds min_interval(100);

std::string throttle_key = std::to_string(iid) + "_" + std::to_string(what);
auto now = std::chrono::steady_clock::now();

if (last_notification_time.find(throttle_key) != last_notification_time.end()) {
    auto time_since_last = now - last_notification_time[throttle_key];
    if (time_since_last < min_interval) {
        // Skip notification to prevent rate limiting
        return;
    }
}
```

### Example 3: Audio Processing
```cpp
// Apply signal quality degradation for poor signal conditions
// This simulates real-world radio behavior where poor signal quality
// causes audio dropouts and distortion
if (signalVolume < 0.3) {  // Poor signal threshold
    float dropoutProbability = (0.3 - signalVolume) * 0.5;  // 0-15% dropout rate
    fgcom_audio_applySignalQualityDegradation(outputPCM, sampleCount, channelCount, dropoutProbability);
}
```

## The Benefits

### 1. **Immediate Bug Prevention**
- Format errors are caught during code review
- Index errors are obvious when documented
- Transformation errors are prevented by clear explanations

### 2. **Faster Debugging**
- Root cause analysis is immediate
- Error messages are self-explanatory
- Code review catches issues before deployment

### 3. **Better Maintainability**
- New developers understand the code immediately
- Modifications are safer with clear constraints
- Testing is more effective with documented behavior

### 4. **Reduced Technical Debt**
- Documentation prevents future bugs
- Code clarity reduces maintenance overhead
- Knowledge transfer is automatic

## The Cost of Poor Documentation

### The Hidden Costs
- Debugging time: Hours spent finding format errors
- Production delays: Bugs discovered in production
- Knowledge loss: Critical information not captured
- Maintenance overhead: Future developers struggle to understand

### The Real Example
The missing comment that would have prevented the bug:
```python
# CRITICAL: NEC2 GW format is exactly: GW tag# segments# x1 y1 z1 x2 y2 z2 radius
# Do NOT add extra fields or the coordinate parsing will be shifted!
```

This single comment would have made the bug **immediately obvious** during code review or debugging. The extra `0` would have stood out like a sore thumb against a comment saying "9 fields exactly: tag segments x1 y1 z1 x2 y2 z2 radius"!

## Conclusion

**ALL code must be self-documenting with clear comments, but NO claims!**

Every line of code must explain:
- **What** it does (factual)
- **Why** it does it (factual)
- **What happens** if it's wrong (factual)
- **Examples** of correct usage (factual)

This is **the most cost-effective bug prevention tool available** - and it saves hours of debugging in every case!

**Remember: The best code is self-documenting, but the best documentation prevents bugs before they happen.**
