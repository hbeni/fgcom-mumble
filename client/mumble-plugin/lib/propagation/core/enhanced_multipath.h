/*
 * Enhanced Multipath Implementation
 * 
 * This file provides advanced multipath modeling for radio propagation
 * including complex scenarios, fading patterns, and interference effects.
 */

#ifndef FGCOM_ENHANCED_MULTIPATH_H
#define FGCOM_ENHANCED_MULTIPATH_H

#include <vector>
#include <complex>
#include <map>
#include <string>
#include <chrono>

// Multipath component structure
struct MultipathComponent {
    float amplitude;
    float phase;
    float delay_ns;
    float doppler_shift_hz;
    float angle_of_arrival_deg;
    float angle_of_departure_deg;
    std::string component_type; // "direct", "reflected", "diffracted", "scattered"
    float power_db;
    float coherence_time_ms;
};

// Multipath channel model
struct MultipathChannel {
    std::vector<MultipathComponent> components;
    float total_power_db;
    float rms_delay_spread_ns;
    float coherence_bandwidth_hz;
    float coherence_time_ms;
    float doppler_spread_hz;
    bool is_wideband;
    bool is_fast_fading;
    std::string channel_type; // "rural", "urban", "indoor", "highway"
};

// Multipath calculation parameters
struct MultipathCalculationParams {
    float frequency_hz;
    float bandwidth_hz;
    float distance_km;
    float tx_altitude_m;
    float rx_altitude_m;
    float tx_power_watts;
    bool enable_ground_reflection;
    bool enable_building_scattering;
    bool enable_vegetation_effects;
    bool enable_vehicle_scattering;
    float terrain_roughness_m;
    float building_density;
    float vegetation_density;
    float vehicle_density;
};

// Fading statistics
struct FadingStatistics {
    float mean_power_db;
    float variance_db;
    float skewness;
    float kurtosis;
    float rms_delay_spread_ns;
    float coherence_bandwidth_hz;
    float coherence_time_ms;
    float doppler_spread_hz;
    int num_components;
    float k_factor_db; // Ricean K-factor
};

// Enhanced multipath calculator class
class FGCom_EnhancedMultipath {
private:
    std::map<std::string, MultipathChannel> channel_cache;
    std::chrono::system_clock::time_point last_cache_update;
    bool cache_enabled;
    float cache_timeout_seconds;
    
    // Multipath component generation
    std::vector<MultipathComponent> generateMultipathComponents(const MultipathCalculationParams& params);
    std::string generateChannelId(const MultipathCalculationParams& params);
    MultipathComponent generateDirectPath(const MultipathCalculationParams& params);
    MultipathComponent generateGroundReflection(const MultipathCalculationParams& params);
    std::vector<MultipathComponent> generateBuildingScattering(const MultipathCalculationParams& params);
    std::vector<MultipathComponent> generateVegetationScattering(const MultipathCalculationParams& params);
    std::vector<MultipathComponent> generateVehicleScattering(const MultipathCalculationParams& params);
    
    // Channel modeling
    MultipathChannel createMultipathChannel(const std::vector<MultipathComponent>& components);
    void calculateChannelStatistics(MultipathChannel& channel);
    void applyFadingEffects(MultipathChannel& channel, float time_ms);
    
    // Signal processing
    std::complex<float> calculateReceivedSignal(const MultipathChannel& channel, float time_ms);
    float calculateSignalPower(const MultipathChannel& channel);
    float calculateSNR(const MultipathChannel& channel, float noise_power_db);
    
    // Advanced modeling
    float calculatePathLoss(const MultipathCalculationParams& params);
    float calculateShadowing(const MultipathCalculationParams& params);
    float calculateFastFading(const MultipathChannel& channel, float time_ms);
    
public:
    FGCom_EnhancedMultipath();
    ~FGCom_EnhancedMultipath();
    
    // Main multipath analysis
    MultipathChannel analyzeMultipathChannel(const MultipathCalculationParams& params);
    
    // Signal quality calculation
    float calculateSignalQuality(const MultipathChannel& channel, float time_ms);
    float calculateBitErrorRate(const MultipathChannel& channel, float snr_db);
    float calculateThroughput(const MultipathChannel& channel, float snr_db);
    
    // Fading analysis
    FadingStatistics calculateFadingStatistics(const MultipathChannel& channel);
    bool isFastFading(const MultipathChannel& channel);
    bool isWidebandFading(const MultipathChannel& channel);
    
    // Channel prediction
    MultipathChannel predictChannelEvolution(const MultipathChannel& current_channel, 
                                           float time_advance_ms);
    
    // Cache management
    void setCacheEnabled(bool enabled, float timeout_seconds = 60.0f);
    void clearCache();
    void updateCache(const std::string& channel_id, const MultipathChannel& channel);
    
    // Configuration
    void setTerrainRoughness(float roughness_m);
    void setBuildingDensity(float density);
    void setVegetationDensity(float density);
    void setVehicleDensity(float density);
    
    // Statistics
    struct MultipathStatistics {
        int total_analyses;
        int fast_fading_detected;
        int wideband_fading_detected;
        float average_components;
        float average_delay_spread;
        std::chrono::system_clock::time_point last_analysis;
    };
    
    MultipathStatistics getStatistics() const;
    void resetStatistics();
    
private:
    float terrain_roughness;
    float building_density;
    float vegetation_density;
    float vehicle_density;
    MultipathStatistics statistics;
};

// Utility functions for multipath calculations
namespace EnhancedMultipathUtils {
    // Calculate path loss
    float calculatePathLoss(float frequency_hz, float distance_km, float tx_altitude_m, float rx_altitude_m);
    
    // Calculate ground reflection coefficient
    float calculateGroundReflectionCoefficient(float frequency_hz, float grazing_angle_deg, 
                                             float ground_permittivity, float ground_conductivity);
    
    // Calculate building scattering
    float calculateBuildingScattering(float frequency_hz, float building_density, float distance_km);
    
    // Calculate vegetation attenuation
    float calculateVegetationAttenuation(float frequency_hz, float vegetation_density, float path_length_km);
    
    // Calculate vehicle scattering
    float calculateVehicleScattering(float frequency_hz, float vehicle_density, float distance_km);
    
    // Calculate Doppler shift
    float calculateDopplerShift(float frequency_hz, float relative_velocity_ms, float angle_deg);
    
    // Calculate delay spread
    float calculateDelaySpread(const std::vector<MultipathComponent>& components);
    
    // Calculate coherence bandwidth
    float calculateCoherenceBandwidth(float rms_delay_spread_ns);
    
    // Calculate coherence time
    float calculateCoherenceTime(float doppler_spread_hz);
    
    // Generate random phase
    float generateRandomPhase();
    
    // Generate random amplitude (Rayleigh distribution)
    float generateRayleighAmplitude(float mean_power);
    
    // Generate random amplitude (Ricean distribution)
    float generateRiceanAmplitude(float mean_power, float k_factor_db);
    
    // Validate multipath parameters
    bool validateMultipathParameters(const MultipathCalculationParams& params);
}

#endif // FGCOM_ENHANCED_MULTIPATH_H
