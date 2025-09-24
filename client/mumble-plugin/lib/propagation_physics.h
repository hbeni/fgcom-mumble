#ifndef FGCOM_PROPAGATION_PHYSICS_H
#define FGCOM_PROPAGATION_PHYSICS_H

#include <cmath>
#include <string>

/**
 * Advanced Propagation Physics for VHF/UHF Radio Models
 * 
 * This module implements realistic radio propagation calculations including:
 * - Free space path loss
 * - Frequency-dependent path loss
 * - Atmospheric absorption
 * - Tropospheric effects
 * - Terrain and obstruction modeling
 * - Antenna height gain
 */

namespace FGCom_PropagationPhysics {

    // Physical constants
    constexpr double SPEED_OF_LIGHT = 299792458.0;  // m/s
    constexpr double EARTH_RADIUS = 6371000.0;      // m
    constexpr double ATMOSPHERIC_REFRACTION_FACTOR = 1.33;  // Standard atmospheric refraction

    /**
     * Calculate free space path loss in dB
     * 
     * @param distance_km Distance in kilometers
     * @param frequency_mhz Frequency in MHz
     * @return Path loss in dB
     */
    double calculateFreeSpacePathLoss(double distance_km, double frequency_mhz);

    /**
     * Calculate atmospheric absorption loss in dB
     * 
     * @param distance_km Distance in kilometers
     * @param frequency_mhz Frequency in MHz
     * @param altitude_m Altitude in meters
     * @param temperature_c Temperature in Celsius
     * @param humidity_percent Relative humidity percentage
     * @return Atmospheric absorption loss in dB
     */
    double calculateAtmosphericAbsorption(double distance_km, double frequency_mhz, 
                                        double altitude_m, double temperature_c, 
                                        double humidity_percent);

    /**
     * Calculate tropospheric ducting effects for VHF
     * 
     * @param distance_km Distance in kilometers
     * @param frequency_mhz Frequency in MHz
     * @param altitude_m Altitude in meters
     * @param temperature_c Temperature in Celsius
     * @param humidity_percent Relative humidity percentage
     * @return Ducting gain/loss in dB
     */
    double calculateTroposphericDucting(double distance_km, double frequency_mhz,
                                      double altitude_m, double temperature_c,
                                      double humidity_percent);

    /**
     * Calculate antenna height gain
     * 
     * @param antenna_height_m Antenna height in meters
     * @param frequency_mhz Frequency in MHz
     * @param distance_km Distance in kilometers
     * @return Height gain in dB
     */
    double calculateAntennaHeightGain(double antenna_height_m, double frequency_mhz, 
                                     double distance_km);

    /**
     * Calculate terrain obstruction loss
     * 
     * @param distance_km Distance in kilometers
     * @param frequency_mhz Frequency in MHz
     * @param obstruction_height_m Obstruction height in meters
     * @param antenna_height_m Antenna height in meters
     * @return Obstruction loss in dB
     */
    double calculateTerrainObstructionLoss(double distance_km, double frequency_mhz,
                                         double obstruction_height_m, double antenna_height_m);

    /**
     * Calculate rain attenuation for UHF
     * 
     * @param distance_km Distance in kilometers
     * @param frequency_mhz Frequency in MHz
     * @param rain_rate_mmh Rain rate in mm/h
     * @return Rain attenuation in dB
     */
    double calculateRainAttenuation(double distance_km, double frequency_mhz, 
                                   double rain_rate_mmh);

    /**
     * Calculate total propagation loss with all effects
     * 
     * @param distance_km Distance in kilometers
     * @param frequency_mhz Frequency in MHz
     * @param altitude_m Altitude in meters
     * @param antenna_height_m Antenna height in meters
     * @param temperature_c Temperature in Celsius
     * @param humidity_percent Relative humidity percentage
     * @param rain_rate_mmh Rain rate in mm/h
     * @param obstruction_height_m Obstruction height in meters
     * @return Total propagation loss in dB
     */
    double calculateTotalPropagationLoss(double distance_km, double frequency_mhz,
                                       double altitude_m, double antenna_height_m,
                                       double temperature_c, double humidity_percent,
                                       double rain_rate_mmh, double obstruction_height_m);

    /**
     * Convert dB loss to linear multiplier
     * 
     * @param loss_db Loss in dB
     * @return Linear multiplier (0.0 to 1.0)
     */
    double dbToLinear(double loss_db);

    /**
     * Convert linear multiplier to dB
     * 
     * @param linear Linear multiplier (0.0 to 1.0)
     * @return Loss in dB
     */
    double linearToDb(double linear);

    /**
     * Get atmospheric conditions for a given location and time
     * This is a simplified model - in real implementation would use weather data
     */
    struct AtmosphericConditions {
        double temperature_c;
        double humidity_percent;
        double pressure_hpa;
        double rain_rate_mmh;
        
        AtmosphericConditions() : temperature_c(20.0), humidity_percent(50.0), 
                                pressure_hpa(1013.25), rain_rate_mmh(0.0) {}
    };

    /**
     * Get atmospheric conditions for a location
     * Simplified model - in production would integrate with weather APIs
     */
    AtmosphericConditions getAtmosphericConditions(double latitude, double longitude, 
                                                  double altitude_m);

} // namespace FGCom_PropagationPhysics

#endif // FGCOM_PROPAGATION_PHYSICS_H
