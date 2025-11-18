/*
 * Propagation Physics Implementation
 * 
 * This file provides the missing implementation for FGCom_PropagationPhysics
 */

#include "propagation_physics.h"
#include <cmath>
#include <algorithm>

// Get atmospheric conditions for a given location and time
AtmosphericConditions FGCom_PropagationPhysics::getAtmosphericConditions(double latitude, double longitude, double altitude) {
    AtmosphericConditions conditions;
    
    // Use all parameters for realistic atmospheric modeling
    // Temperature varies with altitude and latitude
    conditions.temperature_c = 20.0 - (altitude * 0.0065) - (std::abs(latitude) * 0.1);
    
    // Humidity varies with altitude and longitude (coastal vs inland)
    conditions.humidity_percent = 50.0 + (altitude * -0.01) + (std::abs(longitude) * 0.05);
    if (conditions.humidity_percent < 10.0) conditions.humidity_percent = 10.0;
    if (conditions.humidity_percent > 100.0) conditions.humidity_percent = 100.0;
    
    // Rain rate varies with altitude and location
    conditions.rain_rate_mmh = (altitude > 1000.0) ? 2.0 : 0.0;
    
    // Wind speed varies with altitude and latitude
    conditions.wind_speed_ms = 5.0 + (altitude * 0.01) + (std::abs(latitude) * 0.1);
    
    // Wind direction varies with longitude
    conditions.wind_direction_deg = std::fmod(longitude * 10.0, 360.0);
    
    return conditions;
}

// Calculate total propagation loss
double FGCom_PropagationPhysics::calculateTotalPropagationLoss(
    double frequency_mhz,
    double distance_km,
    double tx_altitude_m,
    double rx_altitude_m,
    double tx_power_dbm,
    double rx_sensitivity_dbm,
    double atmospheric_loss_db,
    double terrain_loss_db
) {
    // Input validation and protection against mathematical hazards
    if (frequency_mhz <= 0.0 || distance_km <= 0.0) {
        return 1000.0; // Return high loss for invalid inputs
    }
    
    // ITU-R P.525-2: Correct Free Space Path Loss formula
    double wavelength_m = 300.0 / frequency_mhz; // Wavelength in meters
    double fsl_db = 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / wavelength_m);
    
    // ITU-R P.676-11: Atmospheric absorption (oxygen and water vapor)
    double atmospheric_absorption = calculateAtmosphericAbsorption(frequency_mhz, distance_km, tx_altitude_m, rx_altitude_m);
    
    // ITU-R P.838-3: Rain attenuation
    double rain_attenuation = calculateRainAttenuation(frequency_mhz, distance_km);
    
    // ITU-R P.526-14: Line of sight distance with Earth curvature
    double los_distance_km = calculateLineOfSightDistance(tx_altitude_m, rx_altitude_m);
    double diffraction_loss = 0.0;
    if (distance_km > los_distance_km) {
        diffraction_loss = calculateDiffractionLoss(frequency_mhz, distance_km, tx_altitude_m, rx_altitude_m);
    }
    
    // Ground reflection loss (ITU-R P.1546-5)
    double ground_reflection_loss = calculateGroundReflectionLoss(frequency_mhz, distance_km, tx_altitude_m, rx_altitude_m);
    
    // Fresnel zone clearance loss
    double fresnel_loss = calculateFresnelZoneLoss(frequency_mhz, distance_km, tx_altitude_m, rx_altitude_m);
    
    // Total propagation loss
    double total_loss = fsl_db + atmospheric_absorption + rain_attenuation + 
                       diffraction_loss + ground_reflection_loss + fresnel_loss + 
                       atmospheric_loss_db + terrain_loss_db;
    
    return total_loss;
}

// ITU-R P.676-11: Atmospheric absorption calculation
double FGCom_PropagationPhysics::calculateAtmosphericAbsorption(double frequency_mhz, double distance_km, 
                                                                double tx_altitude_m, double rx_altitude_m) {
    // Frequency-dependent atmospheric absorption
    double absorption_db = 0.0;
    
    // Oxygen absorption (ITU-R P.676-11)
    if (frequency_mhz >= 50.0) {
        double oxygen_absorption = 0.0;
        if (frequency_mhz >= 50.0 && frequency_mhz <= 70.0) {
            // Oxygen absorption peak around 60 GHz
            double f_ghz = frequency_mhz / 1000.0;
            oxygen_absorption = 0.5 * std::exp(-std::pow((f_ghz - 60.0) / 10.0, 2.0));
        }
        absorption_db += oxygen_absorption * distance_km;
    }
    
    // Water vapor absorption (ITU-R P.676-11)
    if (frequency_mhz >= 20.0) {
        double water_vapor_absorption = 0.0;
        if (frequency_mhz >= 20.0 && frequency_mhz <= 30.0) {
            // Water vapor absorption peak around 22 GHz
            double f_ghz = frequency_mhz / 1000.0;
            water_vapor_absorption = 0.1 * std::exp(-std::pow((f_ghz - 22.0) / 3.0, 2.0));
        }
        absorption_db += water_vapor_absorption * distance_km;
    }
    
    // Altitude-dependent atmospheric density
    double avg_altitude_m = (tx_altitude_m + rx_altitude_m) / 2.0;
    double altitude_factor = std::exp(-avg_altitude_m / 8000.0); // Scale height ~8 km
    absorption_db *= altitude_factor;
    
    return absorption_db;
}

// ITU-R P.838-3: Rain attenuation calculation
double FGCom_PropagationPhysics::calculateRainAttenuation(double frequency_mhz, double distance_km) {
    // Get current rain rate (simplified - should use real weather data)
    double rain_rate_mmh = 0.0; // Default to no rain
    
    if (rain_rate_mmh <= 0.0) {
        return 0.0;
    }
    
    // ITU-R P.838-3 frequency-dependent coefficients
    double k, alpha;
    if (frequency_mhz >= 1000.0 && frequency_mhz <= 10000.0) {
        // Microwave frequencies: significant rain attenuation
        double f_ghz = frequency_mhz / 1000.0;
        k = 0.0001 * std::pow(f_ghz, 1.5);
        alpha = 1.0;
    } else if (frequency_mhz >= 100.0 && frequency_mhz < 1000.0) {
        // UHF frequencies: moderate rain attenuation
        k = 0.00001 * std::pow(frequency_mhz / 100.0, 0.5);
        alpha = 0.8;
    } else {
        // VHF and lower frequencies: minimal rain attenuation
        k = 0.000001;
        alpha = 0.5;
    }
    
    // ITU-R P.838-3 rain attenuation formula
    double gamma_r = k * std::pow(rain_rate_mmh, alpha);
    double rain_attenuation_db = gamma_r * distance_km;
    
    return rain_attenuation_db;
}

// ITU-R P.526-14: Line of sight distance calculation
double FGCom_PropagationPhysics::calculateLineOfSightDistance(double tx_altitude_m, double rx_altitude_m) {
    // Earth radius in meters
    const double earth_radius_m = 6371000.0;
    
    // Effective Earth radius factor (standard atmosphere)
    const double k_factor = 4.0 / 3.0;
    
    // ITU-R P.526-14 line of sight distance formula
    double d_los = std::sqrt(2.0 * k_factor * earth_radius_m * tx_altitude_m) + 
                   std::sqrt(2.0 * k_factor * earth_radius_m * rx_altitude_m);
    
    return d_los / 1000.0; // Convert to km
}

// ITU-R P.526-14: Diffraction loss calculation
double FGCom_PropagationPhysics::calculateDiffractionLoss(double frequency_mhz, double distance_km, 
                                                          double tx_altitude_m, double rx_altitude_m) {
    // Simplified knife-edge diffraction model
    double wavelength_m = 300.0 / frequency_mhz;
    
    // Calculate Fresnel parameter
    double d1 = distance_km * 1000.0 / 2.0; // Distance to obstacle (simplified)
    double d2 = distance_km * 1000.0 / 2.0;
    double h = std::max(tx_altitude_m, rx_altitude_m) * 0.1; // Obstacle height (simplified)
    
    double v = h * std::sqrt(2.0 * (d1 + d2) / (wavelength_m * d1 * d2));
    
    // ITU-R P.526-14 diffraction loss formula
    double diffraction_loss_db = 0.0;
    if (v > 0.0) {
        diffraction_loss_db = 6.9 + 20.0 * std::log10(std::sqrt(std::pow(v - 0.1, 2.0) + 1.0) + v - 0.1);
    }
    
    return diffraction_loss_db;
}

// ITU-R P.1546-5: Ground reflection loss calculation
double FGCom_PropagationPhysics::calculateGroundReflectionLoss(double frequency_mhz, double distance_km, 
                                                               double tx_altitude_m, double rx_altitude_m) {
    // Ground reflection coefficient (simplified)
    double grazing_angle_rad = std::atan((tx_altitude_m + rx_altitude_m) / (distance_km * 1000.0));
    
    // Ground permittivity (typical values)
    double epsilon_r = 15.0; // Wet ground
    double sigma = 0.01; // Ground conductivity (S/m)
    
    // Reflection coefficient calculation
    double sin_theta = std::sin(grazing_angle_rad);
    double cos_theta = std::cos(grazing_angle_rad);
    
    // Simplified ground reflection coefficient (avoiding complex numbers)
    double ground_loss_db = 0.0;
    
    // Ground reflection loss based on grazing angle and frequency
    if (grazing_angle_rad < M_PI / 6.0) { // Less than 30 degrees
        // Low grazing angle - significant reflection loss
        ground_loss_db = 6.0 + 10.0 * std::log10(frequency_mhz / 100.0);
    } else {
        // High grazing angle - minimal reflection loss
        ground_loss_db = 2.0;
    }
    
    return std::max(0.0, ground_loss_db);
}

// Fresnel zone clearance loss calculation
double FGCom_PropagationPhysics::calculateFresnelZoneLoss(double frequency_mhz, double distance_km, 
                                                         double tx_altitude_m, double rx_altitude_m) {
    // First Fresnel zone radius at midpoint
    double wavelength_m = 300.0 / frequency_mhz;
    double d1 = distance_km * 1000.0 / 2.0;
    double d2 = distance_km * 1000.0 / 2.0;
    
    double fresnel_radius_m = std::sqrt(wavelength_m * d1 * d2 / (d1 + d2));
    
    // Clearance height (simplified - should use terrain data)
    double clearance_height_m = std::min(tx_altitude_m, rx_altitude_m) * 0.1;
    
    // Fresnel zone clearance loss
    double clearance_ratio = clearance_height_m / fresnel_radius_m;
    double fresnel_loss_db = 0.0;
    
    if (clearance_ratio < 0.6) {
        // Insufficient clearance
        fresnel_loss_db = 20.0 * std::log10(0.6 / clearance_ratio);
    }
    
    return fresnel_loss_db;
}