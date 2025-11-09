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
- `mumble_onAudioSourceFetched()` is ONLY called when `isSpeech == true`
- `isSpeech` is true only when someone is actively transmitting
- Therefore: White noise code NEVER executes when channel is silent
- Result: No white noise at 0% squelch when nobody is speaking

### The Correct Solution

White noise should be generated **independently** of incoming speech. There are two approaches:

#### **Approach A: Generate on Audio Input (Recommended)**

Modify `mumble_onAudioInput()` to add white noise to the local user's microphone stream when receiving.

**Location:** Around line 1140 in `fgcom-mumble.cpp`

**Add this code at the END of `mumble_onAudioInput()`, BEFORE the return statement:**

```cpp
bool mumble_onAudioInput(short *inputPCM, uint32_t sampleCount, uint16_t channelCount, bool isSpeech) {
    // ... existing code ...
    
    // Generate white noise for local monitoring when squelch is open
    // This simulates radio static when tuned with open squelch
    if (fgcom_isPluginActive() && fgcom_cfg.radioAudioEffects) {
        // Quick check for open squelch - use local state only
        bool shouldGenerateNoise = false;
        float bestNoiseLevel = 0.0f;
        const float SQUELCH_OPEN_THRESHOLD = 0.1f;
        const float MAX_NOISE_VOLUME = 0.3f;
        
        // Try to check radio state - if we can't get lock, skip this frame
        if (fgcom_localcfg_mtx.try_lock()) {
            for (const auto &lcl_idty : fgcom_local_client) {
                const fgcom_client& lcl = lcl_idty.second;
                for (const auto &radio : lcl.radios) {
                    if (radio.operable && !radio.frequency.empty() && 
                        radio.squelch <= SQUELCH_OPEN_THRESHOLD && !radio.ptt) {
                        float noiseLevel = (1.0f - (radio.squelch / SQUELCH_OPEN_THRESHOLD)) * MAX_NOISE_VOLUME;
                        if (noiseLevel > bestNoiseLevel) {
                            bestNoiseLevel = noiseLevel;
                            shouldGenerateNoise = true;
                        }
                    }
                }
            }
            fgcom_localcfg_mtx.unlock();
        }
        
        if (shouldGenerateNoise && bestNoiseLevel > 0.0f) {
            // Convert short* PCM to float* for noise addition, then back
            // Allocate temporary float buffer
            float *tempPCM = new float[sampleCount * channelCount];
            
            // Convert from short to float [-1.0, 1.0]
            for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
                tempPCM[i] = inputPCM[i] / 32768.0f;
            }
            
            // Add noise
            fgcom_audio_addNoise(bestNoiseLevel, tempPCM, sampleCount, channelCount);
            
            // Convert back to short
            for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
                float sample = tempPCM[i] * 32768.0f;
                if (sample > 32767.0f) sample = 32767.0f;
                if (sample < -32768.0f) sample = -32768.0f;
                inputPCM[i] = (short)sample;
            }
            
            delete[] tempPCM;
            return true;
        }
    }
    
    return false;
}
```

**Note:** This approach adds noise to YOUR microphone input, so you hear it locally.

#### **Approach B: Separate Background Noise Thread (Alternative)**

Create a dedicated low-priority thread that generates background noise audio and injects it into Mumble's audio system. This is more complex but cleaner architecturally.

**Not recommended due to complexity.**

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

The audio input approach works because:
- You control when it's called (only when you're transmitting or have mic open)
- It's in your own thread context
- It doesn't interfere with Mumble's internal audio processing

---

## Summary of Required Changes

### Files to Modify:
1. `fgcom-mumble.cpp` - Implement white noise in `mumble_onAudioInput()`
2. `io_UDPServer.cpp` - Add 5 logging points

### Code to Remove:
1. Delete entire `mumble_onAudioOutputAboutToPlay()` function if it exists

### Code to Add:
1. White noise generation in audio input callback (~50 lines)
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
- Use fixed-size arrays instead of vectors for performance
- Clean up temporary allocations (delete[] tempPCM)

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
1. **White noise code in wrong callback** - move to audio input
2. **Missing logging** - add 5-6 log points
3. **Audio output callback causes deadlock** - remove it entirely

These fixes are straightforward and will resolve the white noise issue while providing full debugging visibility.

I have tried to fix these issues, but it very often results in Mumble freezing if one tries to reload or install the plugin
