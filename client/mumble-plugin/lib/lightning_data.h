/*
 * Lightning Data API for FGCom-mumble
 * Provides lightning strike structures and utilities
 */

#ifndef LIGHTNING_DATA_H
#define LIGHTNING_DATA_H

#include <string>
#include <chrono>
#include <vector>

namespace FGComLightning {

// Lightning strike data structure
struct LightningStrike {
    double latitude;
    double longitude;
    float intensity_ka;
    std::string type; // "cloud-to-ground", "cloud-to-cloud", "intra-cloud"
    std::chrono::system_clock::time_point timestamp;
    bool is_valid;
    
    LightningStrike() : latitude(0.0), longitude(0.0), intensity_ka(0.0f), 
                       type("cloud-to-ground"), is_valid(false) {
        timestamp = std::chrono::system_clock::now();
    }
};

// Lightning data cache for performance
struct LightningDataCache {
    std::vector<LightningStrike> recent_strikes;
    std::chrono::system_clock::time_point last_update;
    bool is_valid;
    
    LightningDataCache() : is_valid(false) {
        last_update = std::chrono::system_clock::now();
    }
};

// Lightning data API functions
class LightningDataAPI {
public:
    static std::vector<LightningStrike> getCurrentStrikes(double lat, double lon, double radius_km);
    static std::vector<LightningStrike> getStrikesInArea(double min_lat, double max_lat, 
                                                         double min_lon, double max_lon);
    static bool submitLightningData(const LightningStrike& strike);
    static bool submitLightningDataBatch(const std::vector<LightningStrike>& strikes);
    static bool updateLightningData(const std::string& strike_id, const LightningStrike& strike);
};

} // namespace FGComLightning

#endif // LIGHTNING_DATA_H
