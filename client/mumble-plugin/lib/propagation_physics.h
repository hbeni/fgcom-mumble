/*
 * Propagation Physics Header
 * 
 * This file declares the FGCom_PropagationPhysics class
 */

#ifndef PROPAGATION_PHYSICS_H
#define PROPAGATION_PHYSICS_H

#include <string>

// Atmospheric conditions structure
struct AtmosphericConditions {
    double temperature_c;
    double humidity_percent;
    double rain_rate_mmh;
    double wind_speed_ms;
    double wind_direction_deg;
};

class FGCom_PropagationPhysics {
public:
    // Get atmospheric conditions for a given location and time
    static AtmosphericConditions getAtmosphericConditions(double latitude, double longitude, double altitude);
    
    // Calculate total propagation loss
    static double calculateTotalPropagationLoss(
        double frequency_mhz,
        double distance_km,
        double tx_altitude_m,
        double rx_altitude_m,
        double tx_power_dbm,
        double rx_sensitivity_dbm,
        double atmospheric_loss_db,
        double terrain_loss_db
    );
};

#endif // PROPAGATION_PHYSICS_H