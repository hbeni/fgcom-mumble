#ifndef FGCOM_THREADING_TYPES_H
#define FGCOM_THREADING_TYPES_H

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <atomic>
#include <memory>

// Forward declarations for threading system
struct PropagationTask {
    std::string task_id;
    std::string operation_type;
    std::map<std::string, double> parameters;
    std::chrono::system_clock::time_point created_time;
    int priority;
    bool is_completed;
    std::string result_data;
    std::string error_message;
    
    PropagationTask() : priority(0), is_completed(false) {
        created_time = std::chrono::system_clock::now();
    }
};

struct GPUComputeTask {
    std::string task_id;
    std::string operation_type;
    void* input_data;
    size_t input_size;
    void* output_data;
    size_t output_size;
    std::map<std::string, float> parameters;
    std::chrono::system_clock::time_point created_time;
    int priority;
    bool is_completed;
    std::string error_message;
    
    GPUComputeTask() : input_data(nullptr), input_size(0), output_data(nullptr), 
                       output_size(0), priority(0), is_completed(false) {
        created_time = std::chrono::system_clock::now();
    }
    
    ~GPUComputeTask() {
        // Cleanup will be handled by the GPU accelerator
    }
};

struct LightningStrike {
    double latitude;
    double longitude;
    std::chrono::system_clock::time_point timestamp;
    float intensity;
    float distance_km;
    std::string type;
    
    LightningStrike() : latitude(0.0), longitude(0.0), intensity(0.0f), distance_km(0.0f) {
        timestamp = std::chrono::system_clock::now();
    }
};

struct WeatherConditions {
    std::string location;
    double latitude;
    double longitude;
    float temperature_celsius;
    float humidity_percent;
    float pressure_hpa;
    float wind_speed_ms;
    float wind_direction_deg;
    float visibility_km;
    std::string conditions;
    std::chrono::system_clock::time_point timestamp;
    
    WeatherConditions() : latitude(0.0), longitude(0.0), temperature_celsius(20.0f),
                         humidity_percent(50.0f), pressure_hpa(1013.25f), wind_speed_ms(0.0f),
                         wind_direction_deg(0.0f), visibility_km(10.0f) {
        timestamp = std::chrono::system_clock::now();
    }
};

struct AntennaPattern {
    std::string pattern_id;
    std::string antenna_type;
    float frequency_mhz;
    std::vector<float> theta_angles;
    std::vector<float> phi_angles;
    std::vector<float> gain_values;
    std::vector<float> phase_values;
    std::chrono::system_clock::time_point last_updated;
    bool is_valid;
    
    AntennaPattern() : frequency_mhz(0.0f), is_valid(false) {
        last_updated = std::chrono::system_clock::now();
    }
};

// Forward declaration for solar conditions
struct fgcom_solar_conditions;

#endif // FGCOM_THREADING_TYPES_H



