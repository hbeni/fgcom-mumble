#include <rapidcheck.h>
#include <rapidcheck/gtest.h>
#include <gtest/gtest.h>
#include <cmath>
#include <algorithm>
#include <vector>
#include <limits>

// Mock radio propagation classes for property-based testing
class RadioPropagation {
public:
    struct Position {
        double latitude;
        double longitude;
        double altitude;
    };
    
    struct AtmosphericConditions {
        double temperature_c;
        double humidity_percent;
        double rain_rate_mmh;
        double wind_speed_ms;
        double wind_direction_deg;
    };
    
    // Calculate line-of-sight distance
    static double calculateLineOfSight(const Position& pos1, const Position& pos2) {
        const double earth_radius = 6371000.0; // meters
        const double h1 = pos1.altitude;
        const double h2 = pos2.altitude;
        
        // Convert to radians
        double lat1_rad = pos1.latitude * M_PI / 180.0;
        double lon1_rad = pos1.longitude * M_PI / 180.0;
        double lat2_rad = pos2.latitude * M_PI / 180.0;
        double lon2_rad = pos2.longitude * M_PI / 180.0;
        
        // Haversine formula for distance
        double dlat = lat2_rad - lat1_rad;
        double dlon = lon2_rad - lon1_rad;
        double a = sin(dlat/2) * sin(dlat/2) + cos(lat1_rad) * cos(lat2_rad) * sin(dlon/2) * sin(dlon/2);
        double c = 2 * atan2(sqrt(a), sqrt(1-a));
        double distance = earth_radius * c;
        
        // Add altitude difference
        double altitude_diff = h2 - h1;
        return sqrt(distance * distance + altitude_diff * altitude_diff);
    }
    
    // Calculate path loss based on frequency and distance
    static double calculatePathLoss(double frequency_hz, double distance_m) {
        const double c = 299792458.0; // speed of light
        double wavelength = c / frequency_hz;
        double free_space_loss = 20 * log10(4 * M_PI * distance_m / wavelength);
        return free_space_loss;
    }
    
    // Calculate atmospheric attenuation
    static double calculateAtmosphericAttenuation(double frequency_hz, 
                                                   const AtmosphericConditions& conditions) {
        double attenuation = 0.0;
        
        // Rain attenuation (frequency dependent)
        if (frequency_hz > 1e9) { // Above 1 GHz
            double rain_attenuation = 0.0;
            if (conditions.rain_rate_mmh > 0) {
                // ITU-R P.838-3 rain attenuation model
                double k = 0.0001 * pow(frequency_hz / 1e9, 1.5);
                double alpha = 0.8;
                rain_attenuation = k * pow(conditions.rain_rate_mmh, alpha);
            }
            attenuation += rain_attenuation;
        }
        
        // Atmospheric absorption (oxygen and water vapor)
        if (frequency_hz > 10e9) { // Above 10 GHz
            double oxygen_absorption = 0.0;
            double water_vapor_absorption = 0.0;
            
            // Simplified atmospheric absorption model
            if (frequency_hz > 22e9 && frequency_hz < 60e9) {
                oxygen_absorption = 0.1 * (frequency_hz / 1e9 - 22);
            }
            if (frequency_hz > 180e9) {
                water_vapor_absorption = 0.05 * (frequency_hz / 1e9 - 180);
            }
            
            attenuation += oxygen_absorption + water_vapor_absorption;
        }
        
        return attenuation;
    }
    
    // Check if line-of-sight exists (simplified)
    static bool hasLineOfSight(const Position& pos1, const Position& pos2) {
        // Simple check: if both positions are above ground and not too far apart
        return pos1.altitude > 0 && pos2.altitude > 0 && 
               calculateLineOfSight(pos1, pos2) < 100000; // 100km max
    }
};

// Property-based tests for radio propagation
RC_GTEST_PROP(RadioPropagationTests, 
              PathLossIncreasesWithDistance,
              (double frequency_hz, double distance1_m, double distance2_m)) {
    RC_PRE(frequency_hz > 1e6); // At least 1 MHz
    RC_PRE(frequency_hz < 1e12); // At most 1 THz
    RC_PRE(distance1_m > 0);
    RC_PRE(distance2_m > 0);
    RC_PRE(distance1_m < distance2_m);
    
    double loss1 = RadioPropagation::calculatePathLoss(frequency_hz, distance1_m);
    double loss2 = RadioPropagation::calculatePathLoss(frequency_hz, distance2_m);
    
    RC_ASSERT(loss2 > loss1);
}

RC_GTEST_PROP(RadioPropagationTests,
              PathLossIncreasesWithFrequency,
              (double frequency1_hz, double frequency2_hz, double distance_m)) {
    RC_PRE(frequency1_hz > 1e6);
    RC_PRE(frequency2_hz > 1e6);
    RC_PRE(frequency1_hz < frequency2_hz);
    RC_PRE(distance_m > 0);
    
    double loss1 = RadioPropagation::calculatePathLoss(frequency1_hz, distance_m);
    double loss2 = RadioPropagation::calculatePathLoss(frequency2_hz, distance_m);
    
    RC_ASSERT(loss2 > loss1);
}

RC_GTEST_PROP(RadioPropagationTests,
              LineOfSightDistanceIsPositive,
              (RadioPropagation::Position pos1, RadioPropagation::Position pos2)) {
    RC_PRE(pos1.latitude >= -90 && pos1.latitude <= 90);
    RC_PRE(pos1.longitude >= -180 && pos1.longitude <= 180);
    RC_PRE(pos2.latitude >= -90 && pos2.latitude <= 90);
    RC_PRE(pos2.longitude >= -180 && pos2.longitude <= 180);
    RC_PRE(pos1.altitude >= 0);
    RC_PRE(pos2.altitude >= 0);
    
    double distance = RadioPropagation::calculateLineOfSight(pos1, pos2);
    RC_ASSERT(distance >= 0);
}

RC_GTEST_PROP(RadioPropagationTests,
              LineOfSightDistanceIsSymmetric,
              (RadioPropagation::Position pos1, RadioPropagation::Position pos2)) {
    RC_PRE(pos1.latitude >= -90 && pos1.latitude <= 90);
    RC_PRE(pos1.longitude >= -180 && pos1.longitude <= 180);
    RC_PRE(pos2.latitude >= -90 && pos2.latitude <= 90);
    RC_PRE(pos2.longitude >= -180 && pos2.longitude <= 180);
    RC_PRE(pos1.altitude >= 0);
    RC_PRE(pos2.altitude >= 0);
    
    double distance1 = RadioPropagation::calculateLineOfSight(pos1, pos2);
    double distance2 = RadioPropagation::calculateLineOfSight(pos2, pos1);
    
    RC_ASSERT(std::abs(distance1 - distance2) < 1e-6);
}

RC_GTEST_PROP(RadioPropagationTests,
              AtmosphericAttenuationIncreasesWithRain,
              (double frequency_hz, 
               RadioPropagation::AtmosphericConditions conditions1,
               RadioPropagation::AtmosphericConditions conditions2)) {
    RC_PRE(frequency_hz > 1e9); // Above 1 GHz for rain effects
    RC_PRE(conditions1.rain_rate_mmh >= 0);
    RC_PRE(conditions2.rain_rate_mmh >= 0);
    RC_PRE(conditions1.rain_rate_mmh < conditions2.rain_rate_mmh);
    
    double attenuation1 = RadioPropagation::calculateAtmosphericAttenuation(frequency_hz, conditions1);
    double attenuation2 = RadioPropagation::calculateAtmosphericAttenuation(frequency_hz, conditions2);
    
    RC_ASSERT(attenuation2 >= attenuation1);
}

RC_GTEST_PROP(RadioPropagationTests,
              AtmosphericAttenuationIsNonNegative,
              (double frequency_hz, RadioPropagation::AtmosphericConditions conditions)) {
    RC_PRE(frequency_hz > 1e6);
    RC_PRE(conditions.temperature_c >= -50 && conditions.temperature_c <= 50);
    RC_PRE(conditions.humidity_percent >= 0 && conditions.humidity_percent <= 100);
    RC_PRE(conditions.rain_rate_mmh >= 0);
    RC_PRE(conditions.wind_speed_ms >= 0);
    
    double attenuation = RadioPropagation::calculateAtmosphericAttenuation(frequency_hz, conditions);
    RC_ASSERT(attenuation >= 0);
}

RC_GTEST_PROP(RadioPropagationTests,
              HigherFrequenciesMoreAffectedByRain,
              (double frequency1_hz, double frequency2_hz, 
               RadioPropagation::AtmosphericConditions conditions)) {
    RC_PRE(frequency1_hz > 1e9);
    RC_PRE(frequency2_hz > 1e9);
    RC_PRE(frequency1_hz < frequency2_hz);
    RC_PRE(conditions.rain_rate_mmh > 0);
    
    double attenuation1 = RadioPropagation::calculateAtmosphericAttenuation(frequency1_hz, conditions);
    double attenuation2 = RadioPropagation::calculateAtmosphericAttenuation(frequency2_hz, conditions);
    
    RC_ASSERT(attenuation2 > attenuation1);
}

RC_GTEST_PROP(RadioPropagationTests,
              LineOfSightConsistency,
              (RadioPropagation::Position pos1, RadioPropagation::Position pos2)) {
    RC_PRE(pos1.latitude >= -90 && pos1.latitude <= 90);
    RC_PRE(pos1.longitude >= -180 && pos1.longitude <= 180);
    RC_PRE(pos2.latitude >= -90 && pos2.latitude <= 90);
    RC_PRE(pos2.longitude >= -180 && pos2.longitude <= 180);
    RC_PRE(pos1.altitude >= 0);
    RC_PRE(pos2.altitude >= 0);
    
    bool has_los = RadioPropagation::hasLineOfSight(pos1, pos2);
    bool has_los_reverse = RadioPropagation::hasLineOfSight(pos2, pos1);
    
    RC_ASSERT(has_los == has_los_reverse);
}

RC_GTEST_PROP(RadioPropagationTests,
              PathLossScalingWithDistance,
              (double frequency_hz, double distance_m, double scale_factor)) {
    RC_PRE(frequency_hz > 1e6);
    RC_PRE(distance_m > 0);
    RC_PRE(scale_factor > 1.0);
    RC_PRE(scale_factor < 10.0);
    
    double loss1 = RadioPropagation::calculatePathLoss(frequency_hz, distance_m);
    double loss2 = RadioPropagation::calculatePathLoss(frequency_hz, distance_m * scale_factor);
    
    // Path loss should increase by approximately 20*log10(scale_factor) dB
    double expected_increase = 20 * log10(scale_factor);
    double actual_increase = loss2 - loss1;
    
    RC_ASSERT(std::abs(actual_increase - expected_increase) < 1.0);
}

RC_GTEST_PROP(RadioPropagationTests,
              FrequencyDependentRainEffects,
              (double vhf_freq, double uhf_freq, double microwave_freq,
               RadioPropagation::AtmosphericConditions conditions)) {
    RC_PRE(vhf_freq >= 30e6 && vhf_freq <= 300e6); // VHF
    RC_PRE(uhf_freq >= 300e6 && uhf_freq <= 3000e6); // UHF
    RC_PRE(microwave_freq >= 3e9 && microwave_freq <= 30e9); // Microwave
    RC_PRE(conditions.rain_rate_mmh > 0);
    
    double vhf_attenuation = RadioPropagation::calculateAtmosphericAttenuation(vhf_freq, conditions);
    double uhf_attenuation = RadioPropagation::calculateAtmosphericAttenuation(uhf_freq, conditions);
    double microwave_attenuation = RadioPropagation::calculateAtmosphericAttenuation(microwave_freq, conditions);
    
    // VHF should have minimal rain attenuation
    RC_ASSERT(vhf_attenuation < 1.0);
    
    // UHF should have moderate rain attenuation
    RC_ASSERT(uhf_attenuation > vhf_attenuation);
    RC_ASSERT(uhf_attenuation < 10.0);
    
    // Microwave should have significant rain attenuation
    RC_ASSERT(microwave_attenuation > uhf_attenuation);
}

// Custom generators for property-based testing
namespace rc {
    template<>
    struct Arbitrary<RadioPropagation::Position> {
        static Gen<RadioPropagation::Position> arbitrary() {
            return gen::construct<RadioPropagation::Position>(
                gen::inRange(-90.0, 90.0),      // latitude
                gen::inRange(-180.0, 180.0),    // longitude
                gen::inRange(0.0, 50000.0)      // altitude (0 to 50km)
            );
        }
    };
    
    template<>
    struct Arbitrary<RadioPropagation::AtmosphericConditions> {
        static Gen<RadioPropagation::AtmosphericConditions> arbitrary() {
            return gen::construct<RadioPropagation::AtmosphericConditions>(
                gen::inRange(-50.0, 50.0),      // temperature
                gen::inRange(0.0, 100.0),       // humidity
                gen::inRange(0.0, 100.0),       // rain rate
                gen::inRange(0.0, 50.0),        // wind speed
                gen::inRange(0.0, 360.0)        // wind direction
            );
        }
    };
}
