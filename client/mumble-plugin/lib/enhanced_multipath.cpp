/*
 * Enhanced Multipath Implementation
 * 
 * This file provides advanced multipath modeling for radio propagation
 * including complex scenarios, fading patterns, and interference effects.
 */

#include "enhanced_multipath.h"
#include <cmath>
#include <algorithm>
#include <random>
#include <iostream>
#include <complex>

// Constructor
FGCom_EnhancedMultipath::FGCom_EnhancedMultipath() 
    : cache_enabled(true), cache_timeout_seconds(60.0f),
      terrain_roughness(1.0f), building_density(0.1f), 
      vegetation_density(0.2f), vehicle_density(0.05f) {
    
    statistics.total_analyses = 0;
    statistics.fast_fading_detected = 0;
    statistics.wideband_fading_detected = 0;
    statistics.average_components = 0.0f;
    statistics.average_delay_spread = 0.0f;
    statistics.last_analysis = std::chrono::system_clock::now();
}

// Destructor
FGCom_EnhancedMultipath::~FGCom_EnhancedMultipath() {
    // Cleanup if needed
}

// Main multipath analysis
MultipathChannel FGCom_EnhancedMultipath::analyzeMultipathChannel(const MultipathCalculationParams& params) {
    // Check cache first
    std::string channel_id = generateChannelId(params);
    if (cache_enabled) {
        auto it = channel_cache.find(channel_id);
        if (it != channel_cache.end()) {
            auto now = std::chrono::system_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_cache_update);
            if (duration.count() < cache_timeout_seconds) {
                return it->second;
            }
        }
    }
    
    // Generate multipath components
    std::vector<MultipathComponent> components = generateMultipathComponents(params);
    
    // Create multipath channel
    MultipathChannel channel = createMultipathChannel(components);
    
    // Calculate channel statistics
    calculateChannelStatistics(channel);
    
    // Update cache
    if (cache_enabled) {
        channel_cache[channel_id] = channel;
        last_cache_update = std::chrono::system_clock::now();
    }
    
    // Update statistics
    statistics.total_analyses++;
    if (channel.is_fast_fading) {
        statistics.fast_fading_detected++;
    }
    if (channel.is_wideband) {
        statistics.wideband_fading_detected++;
    }
    statistics.average_components = 
        (statistics.average_components * (statistics.total_analyses - 1) + 
         channel.components.size()) / statistics.total_analyses;
    statistics.average_delay_spread = 
        (statistics.average_delay_spread * (statistics.total_analyses - 1) + 
         channel.rms_delay_spread_ns) / statistics.total_analyses;
    statistics.last_analysis = std::chrono::system_clock::now();
    
    return channel;
}

// Generate multipath components
std::vector<MultipathComponent> FGCom_EnhancedMultipath::generateMultipathComponents(const MultipathCalculationParams& params) {
    std::vector<MultipathComponent> components;
    
    // Direct path
    components.push_back(generateDirectPath(params));
    
    // Ground reflection
    if (params.enable_ground_reflection) {
        components.push_back(generateGroundReflection(params));
    }
    
    // Building scattering
    if (params.enable_building_scattering) {
        auto building_components = generateBuildingScattering(params);
        components.insert(components.end(), building_components.begin(), building_components.end());
    }
    
    // Vegetation scattering
    if (params.enable_vegetation_effects) {
        auto vegetation_components = generateVegetationScattering(params);
        components.insert(components.end(), vegetation_components.begin(), vegetation_components.end());
    }
    
    // Vehicle scattering
    if (params.enable_vehicle_scattering) {
        auto vehicle_components = generateVehicleScattering(params);
        components.insert(components.end(), vehicle_components.begin(), vehicle_components.end());
    }
    
    return components;
}

// Generate direct path
MultipathComponent FGCom_EnhancedMultipath::generateDirectPath(const MultipathCalculationParams& params) {
    (void)params; // Suppress unused parameter warning
    MultipathComponent component;
    component.amplitude = 1.0f;
    component.phase = 0.0f;
    component.delay_ns = 0.0f;
    component.doppler_shift_hz = 0.0f;
    component.angle_of_arrival_deg = 0.0f;
    component.angle_of_departure_deg = 0.0f;
    component.component_type = "direct";
    component.power_db = 0.0f;
    component.coherence_time_ms = 1000.0f;
    
    return component;
}

// Generate ground reflection
MultipathComponent FGCom_EnhancedMultipath::generateGroundReflection(const MultipathCalculationParams& params) {
    MultipathComponent component;
    
    // Calculate reflection coefficient
    float grazing_angle = std::atan((params.tx_altitude_m + params.rx_altitude_m) / (params.distance_km * 1000.0f));
    float reflection_coefficient = EnhancedMultipathUtils::calculateGroundReflectionCoefficient(
        params.frequency_hz, grazing_angle * 180.0f / M_PI, 15.0f, 0.01f);
    
    component.amplitude = reflection_coefficient;
    component.phase = M_PI; // 180 degree phase shift
    component.delay_ns = 2.0f * (params.tx_altitude_m + params.rx_altitude_m) / 299792458.0f * 1e9f;
    component.doppler_shift_hz = 0.0f;
    component.angle_of_arrival_deg = -grazing_angle * 180.0f / M_PI;
    component.angle_of_departure_deg = grazing_angle * 180.0f / M_PI;
    component.component_type = "reflected";
    component.power_db = 20.0f * std::log10(reflection_coefficient);
    component.coherence_time_ms = 500.0f;
    
    return component;
}

// Generate building scattering
std::vector<MultipathComponent> FGCom_EnhancedMultipath::generateBuildingScattering(const MultipathCalculationParams& params) {
    std::vector<MultipathComponent> components;
    
    int num_buildings = static_cast<int>(params.building_density * params.distance_km * 10.0f);
    num_buildings = std::min(num_buildings, 20); // Limit to 20 buildings
    
    for (int i = 0; i < num_buildings; i++) {
        MultipathComponent component;
        
        // Random scattering parameters
        component.amplitude = EnhancedMultipathUtils::generateRayleighAmplitude(0.1f);
        component.phase = EnhancedMultipathUtils::generateRandomPhase();
        component.delay_ns = (i + 1) * 50.0f; // Staggered delays
        component.doppler_shift_hz = 0.0f;
        component.angle_of_arrival_deg = (i * 360.0f / num_buildings) + (rand() % 30 - 15);
        component.angle_of_departure_deg = (i * 360.0f / num_buildings) + (rand() % 30 - 15);
        component.component_type = "scattered";
        component.power_db = 20.0f * std::log10(component.amplitude);
        component.coherence_time_ms = 100.0f;
        
        components.push_back(component);
    }
    
    return components;
}

// Generate vegetation scattering
std::vector<MultipathComponent> FGCom_EnhancedMultipath::generateVegetationScattering(const MultipathCalculationParams& params) {
    std::vector<MultipathComponent> components;
    
    int num_vegetation = static_cast<int>(params.vegetation_density * params.distance_km * 5.0f);
    num_vegetation = std::min(num_vegetation, 15); // Limit to 15 vegetation elements
    
    for (int i = 0; i < num_vegetation; i++) {
        MultipathComponent component;
        
        // Vegetation scattering parameters
        component.amplitude = EnhancedMultipathUtils::generateRayleighAmplitude(0.05f);
        component.phase = EnhancedMultipathUtils::generateRandomPhase();
        component.delay_ns = (i + 1) * 30.0f; // Shorter delays for vegetation
        component.doppler_shift_hz = 0.0f;
        component.angle_of_arrival_deg = (i * 360.0f / num_vegetation) + (rand() % 20 - 10);
        component.angle_of_departure_deg = (i * 360.0f / num_vegetation) + (rand() % 20 - 10);
        component.component_type = "scattered";
        component.power_db = 20.0f * std::log10(component.amplitude);
        component.coherence_time_ms = 200.0f;
        
        components.push_back(component);
    }
    
    return components;
}

// Generate vehicle scattering
std::vector<MultipathComponent> FGCom_EnhancedMultipath::generateVehicleScattering(const MultipathCalculationParams& params) {
    std::vector<MultipathComponent> components;
    
    int num_vehicles = static_cast<int>(params.vehicle_density * params.distance_km * 2.0f);
    num_vehicles = std::min(num_vehicles, 10); // Limit to 10 vehicles
    
    for (int i = 0; i < num_vehicles; i++) {
        MultipathComponent component;
        
        // Vehicle scattering parameters
        component.amplitude = EnhancedMultipathUtils::generateRayleighAmplitude(0.03f);
        component.phase = EnhancedMultipathUtils::generateRandomPhase();
        component.delay_ns = (i + 1) * 20.0f; // Short delays for vehicles
        component.doppler_shift_hz = 0.0f; // Could add vehicle motion
        component.angle_of_arrival_deg = (i * 360.0f / num_vehicles) + (rand() % 15 - 7);
        component.angle_of_departure_deg = (i * 360.0f / num_vehicles) + (rand() % 15 - 7);
        component.component_type = "scattered";
        component.power_db = 20.0f * std::log10(component.amplitude);
        component.coherence_time_ms = 50.0f; // Fast fading for vehicles
        
        components.push_back(component);
    }
    
    return components;
}

// Create multipath channel
MultipathChannel FGCom_EnhancedMultipath::createMultipathChannel(const std::vector<MultipathComponent>& components) {
    MultipathChannel channel;
    channel.components = components;
    channel.total_power_db = 0.0f;
    channel.rms_delay_spread_ns = 0.0f;
    channel.coherence_bandwidth_hz = 0.0f;
    channel.coherence_time_ms = 0.0f;
    channel.doppler_spread_hz = 0.0f;
    channel.is_wideband = false;
    channel.is_fast_fading = false;
    channel.channel_type = "mixed";
    
    // Calculate total power
    float total_power = 0.0f;
    for (const auto& component : components) {
        total_power += std::pow(component.amplitude, 2.0f);
    }
    channel.total_power_db = 10.0f * std::log10(total_power);
    
    // Calculate delay spread
    channel.rms_delay_spread_ns = EnhancedMultipathUtils::calculateDelaySpread(components);
    
    // Calculate coherence bandwidth
    channel.coherence_bandwidth_hz = EnhancedMultipathUtils::calculateCoherenceBandwidth(channel.rms_delay_spread_ns);
    
    // Calculate coherence time
    channel.coherence_time_ms = EnhancedMultipathUtils::calculateCoherenceTime(channel.doppler_spread_hz);
    
    // Determine channel characteristics
    channel.is_wideband = (channel.rms_delay_spread_ns > 100.0f);
    channel.is_fast_fading = (channel.coherence_time_ms < 100.0f);
    
    return channel;
}

// Calculate channel statistics
void FGCom_EnhancedMultipath::calculateChannelStatistics(MultipathChannel& channel) {
    if (channel.components.empty()) return;
    
    // Calculate mean power
    float mean_power = 0.0f;
    for (const auto& component : channel.components) {
        mean_power += std::pow(component.amplitude, 2.0f);
    }
    mean_power /= channel.components.size();
    
    // Calculate variance
    float variance = 0.0f;
    for (const auto& component : channel.components) {
        float diff = std::pow(component.amplitude, 2.0f) - mean_power;
        variance += diff * diff;
    }
    variance /= channel.components.size();
    
    // Update channel parameters
    channel.total_power_db = 10.0f * std::log10(mean_power);
    channel.rms_delay_spread_ns = EnhancedMultipathUtils::calculateDelaySpread(channel.components);
    channel.coherence_bandwidth_hz = EnhancedMultipathUtils::calculateCoherenceBandwidth(channel.rms_delay_spread_ns);
    channel.coherence_time_ms = EnhancedMultipathUtils::calculateCoherenceTime(channel.doppler_spread_hz);
}

// Calculate signal quality
float FGCom_EnhancedMultipath::calculateSignalQuality(const MultipathChannel& channel, float time_ms) {
    if (channel.components.empty()) return 0.0f;
    
    // Calculate received signal
    std::complex<float> received_signal = calculateReceivedSignal(channel, time_ms);
    
    // Calculate signal power
    float signal_power = std::norm(received_signal);
    
    // Calculate SNR (simplified)
    float noise_power = 1e-12f; // Thermal noise
    float snr = signal_power / noise_power;
    
    // Convert to dB
    float snr_db = 10.0f * std::log10(snr);
    
    // Calculate signal quality (0 to 1)
    float quality = std::min(1.0f, std::max(0.0f, (snr_db + 20.0f) / 40.0f));
    
    return quality;
}

// Calculate received signal
std::complex<float> FGCom_EnhancedMultipath::calculateReceivedSignal(const MultipathChannel& channel, float time_ms) {
    std::complex<float> received_signal(0.0f, 0.0f);
    
    for (const auto& component : channel.components) {
        // Calculate phase including Doppler shift
        float phase = component.phase + 2.0f * M_PI * component.doppler_shift_hz * time_ms / 1000.0f;
        
        // Calculate amplitude with fading
        float amplitude = component.amplitude * calculateFastFading(channel, time_ms);
        
        // Add component to received signal
        std::complex<float> component_signal = amplitude * std::exp(std::complex<float>(0.0f, phase));
        received_signal += component_signal;
    }
    
    return received_signal;
}

// Calculate fast fading
float FGCom_EnhancedMultipath::calculateFastFading(const MultipathChannel& channel, float time_ms) {
    if (!channel.is_fast_fading) return 1.0f;
    
    // Simple fast fading model
    float fading_factor = 1.0f + 0.5f * std::sin(2.0f * M_PI * time_ms / channel.coherence_time_ms);
    
    return std::max(0.1f, fading_factor);
}

// Calculate fading statistics
FadingStatistics FGCom_EnhancedMultipath::calculateFadingStatistics(const MultipathChannel& channel) {
    FadingStatistics stats;
    
    if (channel.components.empty()) {
        stats.mean_power_db = -100.0f;
        stats.variance_db = 0.0f;
        stats.skewness = 0.0f;
        stats.kurtosis = 0.0f;
        stats.rms_delay_spread_ns = 0.0f;
        stats.coherence_bandwidth_hz = 0.0f;
        stats.coherence_time_ms = 0.0f;
        stats.doppler_spread_hz = 0.0f;
        stats.num_components = 0;
        stats.k_factor_db = -100.0f;
        return stats;
    }
    
    // Calculate mean power
    float mean_power = 0.0f;
    for (const auto& component : channel.components) {
        mean_power += std::pow(component.amplitude, 2.0f);
    }
    mean_power /= channel.components.size();
    stats.mean_power_db = 10.0f * std::log10(mean_power);
    
    // Calculate variance
    float variance = 0.0f;
    for (const auto& component : channel.components) {
        float diff = std::pow(component.amplitude, 2.0f) - mean_power;
        variance += diff * diff;
    }
    variance /= channel.components.size();
    stats.variance_db = 10.0f * std::log10(variance);
    
    // Calculate higher moments (simplified)
    stats.skewness = 0.0f; // Simplified
    stats.kurtosis = 3.0f; // Normal distribution
    
    // Channel parameters
    stats.rms_delay_spread_ns = channel.rms_delay_spread_ns;
    stats.coherence_bandwidth_hz = channel.coherence_bandwidth_hz;
    stats.coherence_time_ms = channel.coherence_time_ms;
    stats.doppler_spread_hz = channel.doppler_spread_hz;
    stats.num_components = channel.components.size();
    
    // K-factor (Ricean factor)
    float direct_power = 0.0f;
    float scattered_power = 0.0f;
    for (const auto& component : channel.components) {
        if (component.component_type == "direct") {
            direct_power += std::pow(component.amplitude, 2.0f);
        } else {
            scattered_power += std::pow(component.amplitude, 2.0f);
        }
    }
    stats.k_factor_db = 10.0f * std::log10(direct_power / (scattered_power + 1e-12f));
    
    return stats;
}

// Check if fast fading
bool FGCom_EnhancedMultipath::isFastFading(const MultipathChannel& channel) {
    return channel.is_fast_fading;
}

// Check if wideband fading
bool FGCom_EnhancedMultipath::isWidebandFading(const MultipathChannel& channel) {
    return channel.is_wideband;
}

// Predict channel evolution
MultipathChannel FGCom_EnhancedMultipath::predictChannelEvolution(const MultipathChannel& current_channel, 
                                                                 float time_advance_ms) {
    MultipathChannel predicted_channel = current_channel;
    
    // Apply time evolution to components
    for (auto& component : predicted_channel.components) {
        // Update phase based on Doppler shift
        component.phase += 2.0f * M_PI * component.doppler_shift_hz * time_advance_ms / 1000.0f;
        
        // Update amplitude based on coherence time
        if (component.coherence_time_ms > 0.0f) {
            float coherence_factor = std::exp(-time_advance_ms / component.coherence_time_ms);
            component.amplitude *= coherence_factor;
        }
    }
    
    // Recalculate channel statistics
    calculateChannelStatistics(predicted_channel);
    
    return predicted_channel;
}

// Set cache enabled
void FGCom_EnhancedMultipath::setCacheEnabled(bool enabled, float timeout_seconds) {
    cache_enabled = enabled;
    cache_timeout_seconds = timeout_seconds;
}

// Clear cache
void FGCom_EnhancedMultipath::clearCache() {
    channel_cache.clear();
}

// Update cache
void FGCom_EnhancedMultipath::updateCache(const std::string& channel_id, const MultipathChannel& channel) {
    if (cache_enabled) {
        channel_cache[channel_id] = channel;
        last_cache_update = std::chrono::system_clock::now();
    }
}

// Set terrain roughness
void FGCom_EnhancedMultipath::setTerrainRoughness(float roughness_m) {
    terrain_roughness = roughness_m;
}

// Set building density
void FGCom_EnhancedMultipath::setBuildingDensity(float density) {
    building_density = density;
}

// Set vegetation density
void FGCom_EnhancedMultipath::setVegetationDensity(float density) {
    vegetation_density = density;
}

// Set vehicle density
void FGCom_EnhancedMultipath::setVehicleDensity(float density) {
    vehicle_density = density;
}

// Get statistics
FGCom_EnhancedMultipath::MultipathStatistics FGCom_EnhancedMultipath::getStatistics() const {
    return statistics;
}

// Reset statistics
void FGCom_EnhancedMultipath::resetStatistics() {
    statistics.total_analyses = 0;
    statistics.fast_fading_detected = 0;
    statistics.wideband_fading_detected = 0;
    statistics.average_components = 0.0f;
    statistics.average_delay_spread = 0.0f;
    statistics.last_analysis = std::chrono::system_clock::now();
}

// Generate channel ID
std::string FGCom_EnhancedMultipath::generateChannelId(const MultipathCalculationParams& params) {
    return std::to_string(static_cast<int>(params.frequency_hz)) + "_" +
           std::to_string(static_cast<int>(params.distance_km)) + "_" +
           std::to_string(static_cast<int>(params.tx_altitude_m)) + "_" +
           std::to_string(static_cast<int>(params.rx_altitude_m));
}

// Utility functions
namespace EnhancedMultipathUtils {
    
    // Calculate path loss
    float calculatePathLoss(float frequency_hz, float distance_km, float tx_altitude_m, float rx_altitude_m) {
        float wavelength = 299792458.0f / frequency_hz;
        float free_space_loss = 20.0f * std::log10(4.0f * M_PI * distance_km * 1000.0f / wavelength);
        float height_gain = 20.0f * std::log10((tx_altitude_m * rx_altitude_m) / (4.0f * 4.0f));
        return free_space_loss - height_gain;
    }
    
    // Calculate ground reflection coefficient
    float calculateGroundReflectionCoefficient(float frequency_hz, float grazing_angle_deg,
                                              float ground_permittivity, float ground_conductivity) {
        (void)frequency_hz; // Suppress unused parameter warning
        (void)ground_conductivity; // Suppress unused parameter warning
        float angle_rad = grazing_angle_deg * M_PI / 180.0f;
        float n = std::sqrt(ground_permittivity);
        float reflection_coeff = (std::sin(angle_rad) - n) / (std::sin(angle_rad) + n);
        return std::abs(reflection_coeff);
    }
    
    // Calculate building scattering
    float calculateBuildingScattering(float frequency_hz, float building_density, float distance_km) {
        (void)frequency_hz; // Suppress unused parameter warning
        float scattering_loss = 20.0f * std::log10(1.0f + building_density * distance_km);
        return scattering_loss;
    }
    
    // Calculate vegetation attenuation
    float calculateVegetationAttenuation(float frequency_hz, float vegetation_density, float path_length_km) {
        (void)frequency_hz; // Suppress unused parameter warning
        float attenuation_db = vegetation_density * path_length_km * 0.1f;
        return attenuation_db;
    }
    
    // Calculate vehicle scattering
    float calculateVehicleScattering(float frequency_hz, float vehicle_density, float distance_km) {
        (void)frequency_hz; // Suppress unused parameter warning
        float scattering_loss = 10.0f * std::log10(1.0f + vehicle_density * distance_km);
        return scattering_loss;
    }
    
    // Calculate Doppler shift
    float calculateDopplerShift(float frequency_hz, float relative_velocity_ms, float angle_deg) {
        float angle_rad = angle_deg * M_PI / 180.0f;
        float doppler_shift = frequency_hz * relative_velocity_ms * std::cos(angle_rad) / 299792458.0f;
        return doppler_shift;
    }
    
    // Calculate delay spread
    float calculateDelaySpread(const std::vector<MultipathComponent>& components) {
        if (components.empty()) return 0.0f;
        
        float mean_delay = 0.0f;
        float total_power = 0.0f;
        
        for (const auto& component : components) {
            float power = std::pow(component.amplitude, 2.0f);
            mean_delay += component.delay_ns * power;
            total_power += power;
        }
        
        if (total_power > 0.0f) {
            mean_delay /= total_power;
        }
        
        float rms_delay = 0.0f;
        for (const auto& component : components) {
            float power = std::pow(component.amplitude, 2.0f);
            float delay_diff = component.delay_ns - mean_delay;
            rms_delay += power * delay_diff * delay_diff;
        }
        
        if (total_power > 0.0f) {
            rms_delay = std::sqrt(rms_delay / total_power);
        }
        
        return rms_delay;
    }
    
    // Calculate coherence bandwidth
    float calculateCoherenceBandwidth(float rms_delay_spread_ns) {
        if (rms_delay_spread_ns <= 0.0f) return 1e9f; // Very wide bandwidth
        return 1.0f / (2.0f * M_PI * rms_delay_spread_ns * 1e-9f);
    }
    
    // Calculate coherence time
    float calculateCoherenceTime(float doppler_spread_hz) {
        if (doppler_spread_hz <= 0.0f) return 1000.0f; // Very long coherence time
        return 1.0f / (2.0f * M_PI * doppler_spread_hz);
    }
    
    // Generate random phase
    float generateRandomPhase() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_real_distribution<float> dis(0.0f, 2.0f * M_PI);
        return dis(gen);
    }
    
    // Generate random amplitude (Rayleigh distribution)
    float generateRayleighAmplitude(float mean_power) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_real_distribution<float> dis(0.0f, 1.0f);
        
        float u = dis(gen);
        float v = dis(gen);
        float amplitude = std::sqrt(-2.0f * std::log(u)) * std::cos(2.0f * M_PI * v);
        return amplitude * std::sqrt(mean_power);
    }
    
    // Generate random amplitude (Ricean distribution)
    float generateRiceanAmplitude(float mean_power, float k_factor_db) {
        float k_factor = std::pow(10.0f, k_factor_db / 10.0f);
        float direct_power = mean_power * k_factor / (1.0f + k_factor);
        float scattered_power = mean_power / (1.0f + k_factor);
        
        float direct_amplitude = std::sqrt(direct_power);
        float scattered_amplitude = generateRayleighAmplitude(scattered_power);
        
        return direct_amplitude + scattered_amplitude;
    }
    
    // Validate multipath parameters
    bool validateMultipathParameters(const MultipathCalculationParams& params) {
        return params.frequency_hz > 0.0f &&
               params.bandwidth_hz > 0.0f &&
               params.distance_km > 0.0f &&
               params.tx_altitude_m >= 0.0f &&
               params.rx_altitude_m >= 0.0f &&
               params.tx_power_watts > 0.0f &&
               params.terrain_roughness_m >= 0.0f &&
               params.building_density >= 0.0f && params.building_density <= 1.0f &&
               params.vegetation_density >= 0.0f && params.vegetation_density <= 1.0f &&
               params.vehicle_density >= 0.0f && params.vehicle_density <= 1.0f;
    }
}
