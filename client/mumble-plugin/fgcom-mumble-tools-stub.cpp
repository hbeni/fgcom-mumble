/* 
 * Stub implementation for testing tools
 * Provides minimal symbols needed by audio.cpp and radio models
 * without requiring Mumble plugin APIs
 */

#include "globalVars.h"
#include <vector>
#include <mutex>
#include <atomic>

// Stub implementations of symbols needed by audio.cpp
struct fgcom_config fgcom_cfg;

std::vector<CachedRadioInfo> cached_radio_infos;
std::mutex cached_radio_infos_mtx;

bool fgcom_isPluginActive() {
    return false; // Tools don't run as plugin
}

float getCachedNoiseFloorVolume(double lat, double lon, float freq_mhz) {
    (void)lat; (void)lon; (void)freq_mhz; // Suppress unused warnings
    return 0.0f; // Return default noise floor for tools
}

