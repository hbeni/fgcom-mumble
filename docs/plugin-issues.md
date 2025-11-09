# FGCom-Mumble Plugin Fix Documentation

## Overview
This document outlines the changes needed to fix white noise generation at 0% squelch and add proper logging for debugging radio data reception.

---

## CRITICAL ISSUE: Plugin Reload Freezing Mumble

**Root Cause:** The `mumble_onAudioOutputAboutToPlay()` callback causes deadlock during shutdown.

**Solution:** **REMOVE** the `mumble_onAudioOutputAboutToPlay()` function entirely. This callback runs continuously in Mumble's audio thread and creates race conditions with shutdown code that cannot be safely resolved.

### Action Required:
1. Delete the entire `mumble_onAudioOutputAboutToPlay()` function from `fgcom-mumble.cpp`
2. Do NOT use audio output callbacks for white noise generation

---

## Problem #1: White Noise Not Generated at 0% Squelch

### Root Cause Analysis

**Location:** `fgcom-mumble.cpp`, `mumble_onAudioSourceFetched()` function (around line 1193)

**The Problem:**
```cpp
if (fgcom_isPluginActive() && isSpeech) {
    // White noise generation code is HERE
    // inside this block at lines 1404-1449
}
```

**Why It Fails:**
- The current code only handles the `isSpeech == true` case (line 1193)
- When `isSpeech == false`, the code goes to the `else` block (line 1453) which does nothing
- `mumble_onAudioSourceFetched()` CAN be called with `isSpeech == false` for non-speech audio, but the current code doesn't handle it
- Result: No white noise at 0% squelch when nobody is speaking

### The Correct Solution

White noise should be generated when squelch is open, regardless of whether speech is detected. The fix is to handle the `!isSpeech` case in `mumble_onAudioSourceFetched()`.

**Location:** `fgcom-mumble.cpp`, `mumble_onAudioSourceFetched()` function, around line 1453

**Current Code Structure:**
```cpp
if (fgcom_isPluginActive() && isSpeech) {
    // ... existing speech processing code ...
} else {
    // plugin not active OR no speech detected
    // do nothing, leave the stream alone
    rv = false;
}
```

**Replace the `else` block with:**

```cpp
} else if (fgcom_isPluginActive() && !isSpeech) {
    // Plugin active but no speech detected - generate white noise if squelch is open
    if (fgcom_cfg.radioAudioEffects) {
        float bestNoiseLevel = 0.0f;
        const float SQUELCH_OPEN_THRESHOLD = 0.1f;  // Consider squelch open if <= 0.1 (10%)
        const float MAX_NOISE_VOLUME = 0.3f;  // Maximum white noise volume (30%)
        
        // Thread-safe access: use try_lock to avoid blocking the audio thread
        // If we can't get the lock immediately, skip noise generation for this frame
        if (fgcom_localcfg_mtx.try_lock()) {
            // Make a quick snapshot of squelch values - only copy primitive types
            std::vector<float> squelchValues;
            squelchValues.reserve(8);  // Pre-allocate to avoid reallocation
            for (const auto &lcl_idty : fgcom_local_client) {
                const fgcom_client& lcl = lcl_idty.second;
                for (const auto &radio : lcl.radios) {
                    // Only copy if radio is operable and has frequency set
                    if (radio.operable && !radio.frequency.empty()) {
                        squelchValues.push_back(radio.squelch);
                    }
                }
            }
            fgcom_localcfg_mtx.unlock();
            
            // Process the snapshot without holding the lock
            for (float squelch : squelchValues) {
                if (squelch <= SQUELCH_OPEN_THRESHOLD) {
                    // Calculate noise level based on squelch setting
                    // Lower squelch (closer to 0.0) = more noise
                    // When squelch is 0.0, use maximum noise; when squelch is at threshold, use less noise
                    float noiseLevel = (1.0f - (squelch / SQUELCH_OPEN_THRESHOLD)) * MAX_NOISE_VOLUME;
                    if (noiseLevel > bestNoiseLevel) {
                        bestNoiseLevel = noiseLevel;
                    }
                }
            }
            
            // Generate white noise if any radio has squelch open
            if (bestNoiseLevel > 0.0f) {
                fgcom_audio_addNoise(bestNoiseLevel, outputPCM, sampleCount, channelCount);
                rv = true;  // We modified the audio stream
            }
        }
        // If try_lock failed, silently skip noise generation for this frame
        // This prevents blocking the audio thread
    }
} else {
    // plugin not active OR no speech detected
    // do nothing, leave the stream alone
    rv = false;
}
```

**Why This Works:**
- `mumble_onAudioSourceFetched()` processes **received audio** (what you hear), not your microphone input
- It can be called with `isSpeech == false` for non-speech audio samples
- This approach generates noise in the correct audio stream (output/received audio)
- Uses the same safe pattern as existing code (try_lock, snapshot, process without lock)

### Enhanced Noise Floor Integration (Highly Recommended)

**Note:** The codebase includes advanced noise floor calculation APIs that can account for:
- **Electric Vehicle Charging Stations** (`calculateEVChargingNoise()`)
- **Industrial Facilities** (`calculateIndustrialNoise()`)
- **Power Lines** (`calculatePowerLineNoise()`)
- **Electrical Substations** (`calculateSubstationNoise()`)
- **Power Stations** (`calculatePowerStationNoise()`)
- **Traffic Noise** (`calculateTrafficNoise()`)
- **Atmospheric Noise** (lightning, solar activity)
- **Weather Conditions** (precipitation, humidity)
- **Time of Day** (diurnal variations)
- **Geographic Location** (latitude, longitude, terrain)

These APIs are located in `lib/atmospheric_noise.cpp` and provide realistic noise floor calculations in dBm based on:
- User's geographic position (latitude/longitude)
- Radio frequency
- Environment type (urban, suburban, remote, industrial, etc.)
- Real-time conditions (weather, time of day, charging activity, etc.)

**Current Implementation Limitation:**
The fix above uses a simple fixed volume calculation (`MAX_NOISE_VOLUME = 0.3f`) based only on squelch level. This does **not** use the advanced noise floor APIs, meaning:
- White noise volume is the same regardless of location
- No variation based on nearby infrastructure (EV stations, power lines, etc.)
- No environmental effects (weather, time of day, etc.)

**Highly Recommended Implementation:**

To integrate realistic noise floor calculations, implement the following:

### Step 1: Add Noise Floor Cache Structure

Add to `fgcom-mumble.cpp` (near top with other global variables, around line 100):

```cpp
// Noise floor cache for performance optimization
struct NoiseFloorCacheEntry {
    float noise_floor_db;
    float audio_volume;  // Converted to 0.0-1.0 range
    std::chrono::system_clock::time_point last_calculated;
    double cached_lat;
    double cached_lon;
    float cached_freq_mhz;
    bool is_valid;
    
    NoiseFloorCacheEntry() : noise_floor_db(0.0f), audio_volume(0.0f), 
                             cached_lat(0.0), cached_lon(0.0), cached_freq_mhz(0.0f), is_valid(false) {
        last_calculated = std::chrono::system_clock::now();
    }
};

// Cache for noise floor calculations (key: "lat_lon_freq" as string)
std::map<std::string, NoiseFloorCacheEntry> noise_floor_cache;
std::mutex noise_floor_cache_mtx;
const std::chrono::seconds CACHE_DURATION(5);  // Recalculate every 5 seconds
const double POSITION_THRESHOLD = 0.001;  // ~100m - recalculate if moved more
const float FREQ_THRESHOLD = 0.001f;  // 1 kHz - recalculate if frequency changed
```

### Step 2: Add dBm to Audio Volume Conversion Function

Add this helper function (around line 200):

```cpp
/**
 * Convert noise floor in dBm to audio volume (0.0 to 1.0)
 * 
 * Typical noise floor ranges:
 * - Remote areas: -140 to -130 dBm (S0-S1) -> 0.05-0.10 volume
 * - Suburban: -130 to -120 dBm (S1-S3) -> 0.10-0.15 volume
 * - Urban: -120 to -110 dBm (S3-S5) -> 0.15-0.25 volume
 * - Industrial: -110 to -100 dBm (S5-S7) -> 0.25-0.35 volume
 * - Very noisy: -100 to -90 dBm (S7-S9+) -> 0.35-0.50 volume
 */
float convertNoiseFloorToVolume(float noise_floor_dbm) {
    // Clamp noise floor to reasonable range
    noise_floor_dbm = std::max(-150.0f, std::min(-80.0f, noise_floor_dbm));
    
    // Convert dBm to linear scale (0.0 to 1.0)
    // Formula: volume = (noise_floor_dbm + 150) / 70
    // This maps -150 dBm -> 0.0, -80 dBm -> 1.0
    float volume = (noise_floor_dbm + 150.0f) / 70.0f;
    
    // Apply non-linear curve for more realistic feel
    volume = std::pow(volume, 0.7f);  // Slight compression
    
    // Clamp to maximum reasonable volume (30% max, same as current MAX_NOISE_VOLUME)
    return std::min(0.3f, volume);
}
```

### Step 3: Add Cached Noise Floor Lookup Function

Add this function (around line 250):

```cpp
/**
 * Get cached or calculate noise floor for a radio
 * Returns audio volume (0.0 to 1.0) ready to use
 */
float getCachedNoiseFloorVolume(double lat, double lon, float freq_mhz) {
    // Create cache key
    std::string cache_key = std::to_string(lat) + "_" + std::to_string(lon) + "_" + std::to_string(freq_mhz);
    
    // Check cache with lock
    {
        std::lock_guard<std::mutex> lock(noise_floor_cache_mtx);
        auto it = noise_floor_cache.find(cache_key);
        if (it != noise_floor_cache.end()) {
            NoiseFloorCacheEntry& entry = it->second;
            auto now = std::chrono::system_clock::now();
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - entry.last_calculated);
            
            // Check if cache is still valid
            bool position_changed = (std::abs(entry.cached_lat - lat) > POSITION_THRESHOLD ||
                                     std::abs(entry.cached_lon - lon) > POSITION_THRESHOLD);
            bool freq_changed = std::abs(entry.cached_freq_mhz - freq_mhz) > FREQ_THRESHOLD;
            bool cache_expired = (age > CACHE_DURATION);
            
            if (!position_changed && !freq_changed && !cache_expired && entry.is_valid) {
                // Cache hit - return cached value
                return entry.audio_volume;
            }
        }
    }
    
    // Cache miss or expired - calculate new value
    // This is the expensive operation - do it OUTSIDE the audio callback if possible
    // For now, we'll do it here but it should ideally be done in a background thread
    float noise_floor_db = FGCom_AtmosphericNoise::getInstance().calculateNoiseFloor(
        lat, lon, freq_mhz, EnvironmentType::URBAN  // Or determine from position
    );
    
    float audio_volume = convertNoiseFloorToVolume(noise_floor_db);
    
    // Update cache
    {
        std::lock_guard<std::mutex> lock(noise_floor_cache_mtx);
        NoiseFloorCacheEntry entry;
        entry.noise_floor_db = noise_floor_db;
        entry.audio_volume = audio_volume;
        entry.last_calculated = std::chrono::system_clock::now();
        entry.cached_lat = lat;
        entry.cached_lon = lon;
        entry.cached_freq_mhz = freq_mhz;
        entry.is_valid = true;
        noise_floor_cache[cache_key] = entry;
    }
    
    return audio_volume;
}
```

### Step 4: Modify White Noise Generation Code

Replace the white noise generation in `mumble_onAudioSourceFetched()` (around line 1430-1445):

**OLD CODE:**
```cpp
for (float squelch : squelchValues) {
    if (squelch <= SQUELCH_OPEN_THRESHOLD) {
        float noiseLevel = (1.0f - (squelch / SQUELCH_OPEN_THRESHOLD)) * MAX_NOISE_VOLUME;
        if (noiseLevel > bestNoiseLevel) {
            bestNoiseLevel = noiseLevel;
        }
    }
}
```

**NEW CODE:**
```cpp
// Get position and frequency for noise floor calculation
// We need to get this from the locked data, so we'll store it during the snapshot
struct RadioInfo {
    float squelch;
    double lat;
    double lon;
    float freq_mhz;
};
std::vector<RadioInfo> radioInfos;
radioInfos.reserve(8);

// During lock, copy radio info including position
if (fgcom_localcfg_mtx.try_lock()) {
    for (const auto &lcl_idty : fgcom_local_client) {
        const fgcom_client& lcl = lcl_idty.second;
        for (const auto &radio : lcl.radios) {
            if (radio.operable && !radio.frequency.empty()) {
                RadioInfo info;
                info.squelch = radio.squelch;
                info.lat = lcl.lat;
                info.lon = lcl.lon;
                // Parse frequency string to float
                try {
                    info.freq_mhz = std::stof(radio.frequency);
                } catch (...) {
                    info.freq_mhz = 0.0f;  // Invalid frequency
                }
                radioInfos.push_back(info);
            }
        }
    }
    fgcom_localcfg_mtx.unlock();
}

// Process radios and calculate noise floor
for (const auto& info : radioInfos) {
    if (info.squelch <= SQUELCH_OPEN_THRESHOLD && info.freq_mhz > 0.0f) {
        // Get noise floor-based volume (cached)
        float baseVolume = getCachedNoiseFloorVolume(info.lat, info.lon, info.freq_mhz);
        
        // Apply squelch modulation (lower squelch = more noise)
        float squelchFactor = (1.0f - (info.squelch / SQUELCH_OPEN_THRESHOLD));
        float noiseLevel = baseVolume * squelchFactor;
        
        if (noiseLevel > bestNoiseLevel) {
            bestNoiseLevel = noiseLevel;
        }
    }
}
```

### Step 5: Add Required Includes

Add to top of `fgcom-mumble.cpp` (around line 30):

```cpp
#include "atmospheric_noise.h"  // For noise floor calculations
#include <chrono>                // For cache timing (may already be included)
#include <map>                    // For cache map (may already be included)
#include <cmath>                  // For std::pow, std::abs
```

### Step 6: Optional - Background Thread for Cache Updates

For better performance, consider adding a background thread that pre-calculates noise floor values:

```cpp
// Background thread to update noise floor cache periodically
std::thread noise_floor_update_thread;
std::atomic<bool> noise_floor_thread_running{false};

void noiseFloorUpdateThread() {
    while (noise_floor_thread_running) {
        // Update cache for all active radios
        if (fgcom_localcfg_mtx.try_lock()) {
            for (const auto &lcl_idty : fgcom_local_client) {
                const fgcom_client& lcl = lcl_idty.second;
                for (const auto &radio : lcl.radios) {
                    if (radio.operable && !radio.frequency.empty()) {
                        try {
                            float freq_mhz = std::stof(radio.frequency);
                            // Pre-calculate and cache
                            getCachedNoiseFloorVolume(lcl.lat, lcl.lon, freq_mhz);
                        } catch (...) {
                            // Invalid frequency, skip
                        }
                    }
                }
            }
            fgcom_localcfg_mtx.unlock();
        }
        
        // Sleep for cache update interval
        std::this_thread::sleep_for(CACHE_DURATION);
    }
}

// Start thread in mumble_init() or fgcom_initPlugin()
// Stop thread in mumble_shutdown()
```

### Expected Results:

After implementation, white noise volume will:
- **Vary by location**: Louder in urban/industrial areas, quieter in remote areas
- **Vary by frequency**: Different noise levels for HF vs VHF vs UHF
- **Vary by infrastructure**: Higher near EV stations, power lines, substations
- **Vary by weather**: More noise during storms, lightning
- **Vary by time**: Diurnal variations in atmospheric noise
- **Remain performant**: Cached calculations prevent audio thread blocking

**Performance Considerations:**

The performance issue stems from the **frequency** at which the audio callback runs versus the **complexity** of noise floor calculations:

**1. Audio Callback Frequency:**
- `mumble_onAudioSourceFetched()` is called **hundreds to thousands of times per second**
- Typical audio: 48,000 samples/second, with callbacks every ~512 samples = **~94 calls/second**
- Each call must complete in **< 10 milliseconds** to avoid audio glitches
- Any delay causes audio dropouts, stuttering, or freezing

**2. Noise Floor Calculation Complexity:**

A single `calculateNoiseFloor()` call performs:

**Basic Operations (always):**
- Thermal noise calculation
- Atmospheric noise (frequency-dependent math)
- Man-made noise (environment lookup)
- Weather factor calculation
- Time of day factor
- Frequency-specific adjustments

**Advanced Operations (if enabled):**
- **ITU-R P.372 model**: Complex atmospheric propagation calculations
- **OSM Integration**: Geographic data queries (could query OpenStreetMap API)
- **Population Density**: Geographic database lookups
- **Power Line Analysis**: Distance calculations to nearby power lines
- **Traffic Analysis**: Road network queries and distance calculations
- **Industrial Analysis**: Facility database lookups
- **EV Charging Analysis**: Charging station database queries and distance calculations
- **Substation Analysis**: Electrical infrastructure database lookups
- **Power Station Analysis**: Power plant database queries

**3. Why This Is Expensive:**

Each calculation involves:
- **Mutex locking** (`std::lock_guard<std::mutex>`) - can block if other threads are using it
- **Multiple function calls** (10-15+ separate calculations)
- **Geographic lookups** (latitude/longitude to infrastructure mapping)
- **Database queries** (if OSM/terrain data is queried)
- **Distance calculations** (to nearest EV stations, power lines, etc.)
- **Mathematical operations** (logarithms, exponentials, trigonometric functions)

**Estimated Cost:**
- Simple calculation: **~0.1-1 milliseconds** per call
- Full calculation with all features: **~5-50 milliseconds** per call
- If called 94 times/second: **470-4,700 milliseconds/second** = **47-470% CPU usage** just for noise calculations!

**4. The Problem:**

If we called `calculateNoiseFloor()` every audio frame:
- **Audio would stutter** (callbacks take too long)
- **CPU usage would spike** (hundreds of calculations per second)
- **Mumble would freeze** (audio thread blocked)
- **Battery drain** (on laptops/mobile devices)

**5. Why Caching Is Essential:**

The solution requires:
- **Calculate once** when position/frequency changes (not every frame)
- **Cache the result** in memory
- **Update periodically** (every few seconds, or when position changes significantly)
- **Use cached value** in audio callback (just a simple memory read)

**6. Current Simple Approach:**

The current fix uses:
- **Fixed volume calculation**: `(1.0f - (squelch / 0.1f)) * 0.3f`
- **Cost**: ~0.001 milliseconds (just arithmetic)
- **CPU usage**: Negligible (< 0.1%)
- **Result**: Smooth audio, no performance impact

**7. Trade-off:**

- **Simple approach**: Fast, smooth audio, but unrealistic (same noise everywhere)
- **Noise floor approach**: Realistic (varies by location), but requires caching and background updates

For real-time audio, the simple approach is preferred. The noise floor approach would require a background thread that updates cached values periodically, then the audio callback just reads the cached value.

---

## Problem #2: Missing Logging for Debugging

### Logging Points Needed

Add the following logging to track data flow from Radio GUI to plugin:

### **Log Point 1: UDP Server - Frequency Reception**

**File:** `io_UDPServer.cpp`  
**Location:** After line 303 (where frequency is parsed and stored)

```cpp
// Add immediately after line 303:
pluginLog("[UDP-RX] IID=" + std::to_string(iid) + 
          " COM" + std::to_string(radio_id+1) + 
          " FRQ=" + finalParsedFRQ);
```

### **Log Point 2: UDP Server - PTT Reception (New Format)**

**File:** `io_UDPServer.cpp`  
**Location:** After line 347 (when PTT is set in new format)

```cpp
// Add immediately after line 347:
pluginLog("[UDP-RX] IID=" + std::to_string(iid) + 
          " COM" + std::to_string(radio_id+1) + 
          " PTT=" + std::to_string(parsedPTT));
```

### **Log Point 3: UDP Server - PTT Reception (Compat Mode)**

**File:** `io_UDPServer.cpp`  
**Location:** After line 474 (old PTT compat mode)

```cpp
// Add immediately after line 474:
pluginLog("[UDP-RX-COMPAT] IID=" + std::to_string(iid) + 
          " COM" + std::to_string(i+1) + 
          " PTT=1");
```

### **Log Point 4: UDP Server - Squelch Reception**

**File:** `io_UDPServer.cpp`  
**Location:** After line 365 (when squelch value is updated)

```cpp
// Add immediately after line 365:
pluginLog("[UDP-RX] IID=" + std::to_string(iid) + 
          " COM" + std::to_string(radio_id+1) + 
          " SQC=" + std::to_string(fgcom_local_client[iid].radios[radio_id].squelch));
```

### **Log Point 5: Radio Operable State**

**File:** `io_UDPServer.cpp`  
**Location:** After line 316 (when radio operable state changes)

```cpp
// Add immediately after line 316:
if (fgcom_radio_updateOperable(fgcom_local_client[iid].radios[radio_id])) {
    pluginLog("[UDP-RX] IID=" + std::to_string(iid) + 
              " COM" + std::to_string(radio_id+1) + 
              " OPERABLE=" + std::to_string(fgcom_local_client[iid].radios[radio_id].operable));
    parseResult[iid].radioData.insert(radio_id);
}
```

### **Log Point 6: Audio Processing Entry**

**File:** `fgcom-mumble.cpp`  
**Location:** In `mumble_onAudioSourceFetched()` at line ~1191

```cpp
// Replace existing pluginDbg() with:
if (fgcom_isPluginActive() && isSpeech) {
    pluginLog("[AUDIO-RX] userID=" + std::to_string(userID) + 
              " isSpeech=" + std::to_string(isSpeech) + 
              " sampleCount=" + std::to_string(sampleCount));
```

---

## Testing Checklist

After implementing the fixes, verify:

1. **Squelch Data Reception:**
   - Start RadioGUI and set squelch to 0%
   - Check logs for: `[UDP-RX] IID=0 COM1 SQC=0.000000`
   - Change squelch to 50%
   - Check logs for: `[UDP-RX] IID=0 COM1 SQC=0.500000`

2. **Frequency Data Reception:**
   - Tune radio to 123.450 MHz
   - Check logs for: `[UDP-RX] IID=0 COM1 FRQ=123.450000`

3. **PTT Data Reception:**
   - Press PTT button
   - Check logs for: `[UDP-RX] IID=0 COM1 PTT=1`
   - Release PTT
   - Check logs for: `[UDP-RX] IID=0 COM1 PTT=0`

4. **Radio Operable State:**
   - Turn radio on
   - Check logs for: `[UDP-RX] IID=0 COM1 OPERABLE=1`

5. **White Noise Generation:**
   - Set squelch to 0%
   - Ensure no one is transmitting
   - You should hear white noise/static
   - Set squelch to 100%
   - White noise should stop

---

## Why the Audio Output Callback Doesn't Work

The `mumble_onAudioOutputAboutToPlay()` callback seems like the perfect solution, but it has fatal flaws:

1. **Called at 48kHz rate** (~1000 times per second) - any blocking = audio glitches
2. **Runs in Mumble's audio thread** - separate from main plugin thread
3. **Cannot safely acquire locks** during shutdown - causes deadlock
4. **Race condition with shutdown** - callback may access freed memory
5. **No way to properly synchronize** - Mumble doesn't provide shutdown notification to callbacks

The `mumble_onAudioSourceFetched()` approach works because:
- It processes the received audio stream (what you hear), which is the correct location for white noise
- It can be called with `isSpeech == false` for non-speech audio, allowing continuous noise generation
- Uses safe locking patterns (try_lock) to avoid blocking the audio thread
- Doesn't interfere with Mumble's internal audio processing when implemented correctly

---

## Summary of Required Changes

### Files to Modify:
1. `fgcom-mumble.cpp` - Handle `!isSpeech` case in `mumble_onAudioSourceFetched()` to generate white noise
2. `io_UDPServer.cpp` - Add 5 logging points

### Code to Remove:
1. Delete entire `mumble_onAudioOutputAboutToPlay()` function if it exists

### Code to Add:
1. White noise generation in `mumble_onAudioSourceFetched()` for `!isSpeech` case (~45 lines)
2. Five logging statements (~5 lines each)

### Expected Outcome:
- White noise plays when squelch is at 0% (even when silent)
- Full visibility into UDP data reception
- No freezing on plugin reload
- Proper radio simulation behavior

---

## Notes on Implementation

### Memory Management
- Use `try_lock()` instead of `lock()` to avoid blocking
- Always check plugin active state before accessing shared data
- Use `std::vector` with `reserve()` for predictable memory allocation
- Copy only primitive types (float squelch values) to minimize lock time

### Performance Considerations
- Audio callbacks are performance-critical
- Minimize time holding locks
- No string concatenation in hot paths
- Log only significant events, not every frame

### Thread Safety
- `fgcom_localcfg_mtx` protects `fgcom_local_client`
- Always use try_lock() in audio callbacks
- Check plugin active state after acquiring lock
- Release locks before expensive operations



---

## Conclusion

The core issues are:
1. **White noise code only handles `isSpeech == true` case** - add handling for `!isSpeech` case in `mumble_onAudioSourceFetched()`
2. **Missing logging** - add 5-6 log points
3. **Audio output callback causes deadlock** - remove it entirely

These fixes are straightforward and will resolve the white noise issue while providing full debugging visibility. The key is to handle the `!isSpeech` case in `mumble_onAudioSourceFetched()` where **received audio** (what you hear from other users) is processed. 

**Important Note:** `mumble_onAudioInput()` processes **your microphone input** (what you're transmitting), not received audio. Additionally, Mumble's noise gates and VAD (Voice Activity Detection) mean `mumble_onAudioInput()` may not be called when there's no speech detected, and adding noise there would only affect what you hear locally (if at all), not what you hear from received transmissions. Therefore, white noise must be generated in `mumble_onAudioSourceFetched()` to be audible in received audio streams.

### Note on Noise Floor Capabilities

The codebase includes comprehensive noise floor calculation APIs that can model:
- Electric vehicle charging stations
- Industrial facilities and power infrastructure
- Atmospheric, weather, and environmental effects
- Geographic and time-of-day variations

While the current fix uses a simple fixed-volume approach for performance reasons, the infrastructure exists to integrate realistic noise floor calculations that would make white noise volume vary based on real-world conditions. **This is highly recommended** and should be implemented with proper caching and performance optimization to provide realistic radio simulation.

---

**Implementation Note:**
I have tried to fix these issues, but it very often results in Mumble freezing if one tries to reload or install the plugin. The fix described above uses safe locking patterns (`try_lock()`) and avoids blocking operations to minimize this risk.
