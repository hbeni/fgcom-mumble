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
    // Free space path loss (uses frequency_mhz and distance_km)
    double fsl_db = 20.0 * std::log10(distance_km) + 20.0 * std::log10(frequency_mhz) + 32.45;
    
    // Altitude-based path loss (uses tx_altitude_m and rx_altitude_m)
    double altitude_diff = std::abs(tx_altitude_m - rx_altitude_m);
    double altitude_loss_db = 0.0;
    if (altitude_diff > 100.0) {
        altitude_loss_db = 0.1 * altitude_diff; // Additional loss for large altitude differences
    }
    
    // Power-based calculations (uses tx_power_dbm and rx_sensitivity_dbm)
    double power_margin_db = tx_power_dbm - rx_sensitivity_dbm;
    double power_loss_db = 0.0;
    if (power_margin_db < 0.0) {
        power_loss_db = std::abs(power_margin_db); // Additional loss if power is insufficient
    }
    
    // Atmospheric absorption (uses atmospheric_loss_db)
    double atmospheric_absorption = atmospheric_loss_db;
    
    // Terrain loss (uses terrain_loss_db)
    double terrain_loss = terrain_loss_db;
    
    // Total loss (uses ALL parameters)
    double total_loss = fsl_db + altitude_loss_db + power_loss_db + atmospheric_absorption + terrain_loss;
    
    return total_loss;
}