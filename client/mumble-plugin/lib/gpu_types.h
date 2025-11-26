#ifndef FGCOM_GPU_TYPES_H
#define FGCOM_GPU_TYPES_H

#include <string>
#include <vector>
#include <map>
#include <chrono>

// Forward declarations for GPU acceleration system
struct AntennaGainPoint {
    float theta_deg;
    float phi_deg;
    float gain_dbi;
    float phase_deg;
    
    AntennaGainPoint() : theta_deg(0.0f), phi_deg(0.0f), gain_dbi(0.0f), phase_deg(0.0f) {}
    AntennaGainPoint(float t, float p, float g, float ph) 
        : theta_deg(t), phi_deg(p), gain_dbi(g), phase_deg(ph) {}
};

struct PropagationPath {
    double start_lat;
    double start_lon;
    double end_lat;
    double end_lon;
    float start_alt;
    float end_alt;
    float frequency_mhz;
    float power_watts;
    std::string antenna_type;
    std::string ground_type;
    std::string mode;
    
    PropagationPath() : start_lat(0.0), start_lon(0.0), end_lat(0.0), end_lon(0.0),
                       start_alt(0.0f), end_alt(0.0f), frequency_mhz(14.0f), power_watts(100.0f) {}
};

struct QSOParameters {
    std::string callsign;
    double latitude;
    double longitude;
    float altitude;
    float frequency_mhz;
    float power_watts;
    std::string antenna_type;
    std::string mode;
    std::string band;
    std::chrono::system_clock::time_point timestamp;
    
    QSOParameters() : latitude(0.0), longitude(0.0), altitude(0.0f), 
                     frequency_mhz(14.0f), power_watts(100.0f) {
        timestamp = std::chrono::system_clock::now();
    }
};

#endif // FGCOM_GPU_TYPES_H



