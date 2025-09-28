/**
 * Moon Position Tracking API for EME Communication
 * 
 * This module provides comprehensive moon position tracking including:
 * - Orbital position calculations
 * - Libration effects (longitude and latitude)
 * - Distance and delay calculations
 * - Doppler shift calculations
 * - Manual position override capabilities
 * - Multi-band support (2m, 6m, 70cm, and future bands)
 */

#ifndef MOON_POSITION_TRACKER_H
#define MOON_POSITION_TRACKER_H

#include <string>
#include <vector>
#include <chrono>
#include <memory>

namespace FGCom {

/**
 * Moon orbital position data
 */
struct MoonPosition {
    double distance_km;           // Distance to moon in kilometers
    double right_ascension_deg;   // Right ascension in degrees
    double declination_deg;       // Declination in degrees
    double longitude_libration_deg; // Longitude libration in degrees
    double latitude_libration_deg;  // Latitude libration in degrees
    double phase_angle_deg;       // Moon phase angle (0-360°)
    double illumination_percent;   // Illumination percentage (0-100%)
    std::chrono::system_clock::time_point timestamp;
    
    // Calculated derived values
    double round_trip_delay_seconds;
    double doppler_shift_hz;
    double path_loss_db;
    double libration_distance_km;
};

/**
 * EME communication parameters
 */
struct EMEParameters {
    double frequency_mhz;          // Operating frequency
    double transmit_power_watts;   // Transmit power
    double antenna_gain_dbi;       // Antenna gain
    double system_noise_temp_k;    // System noise temperature
    double bandwidth_hz;           // Receiver bandwidth
    
    // Calculated values
    double effective_radiated_power_dbw;
    double received_power_dbw;
    double signal_to_noise_ratio_db;
    double communication_range_km;
    double wavelength_m;          // Wavelength in meters
    double path_loss_db;           // Free space path loss
    double moon_reflection_loss_db; // Moon reflection losses
    double atmospheric_loss_db;    // Atmospheric absorption
};

/**
 * EME band specifications
 */
struct EMEBandSpec {
    std::string name;              // Band name (e.g., "2m", "6m", "70cm")
    double frequency_mhz;          // Center frequency
    double wavelength_m;           // Wavelength
    double bandwidth_mhz;          // Bandwidth
    double typical_gain_dbi;       // Typical antenna gain
    double noise_temp_k;          // Typical system noise temperature
    bool is_supported;            // Whether band is supported
};

/**
 * Moon position calculation algorithms
 */
enum class MoonCalculationMethod {
    SIMPLIFIED,      // Basic orbital mechanics
    PRECISE,         // High-precision astronomical calculations
    OVERRIDE         // Manual position override
};

/**
 * Moon Position Tracker Class
 * 
 * Provides comprehensive moon position tracking for EME communication
 * including orbital mechanics, libration effects, and delay calculations
 */
class MoonPositionTracker {
public:
    /**
     * Constructor
     * @param calculation_method Method for position calculations
     */
    explicit MoonPositionTracker(MoonCalculationMethod calculation_method = MoonCalculationMethod::PRECISE);
    
    /**
     * Destructor
     */
    ~MoonPositionTracker() = default;
    
    // Core position tracking methods
    
    /**
     * Get current moon position
     * @return Current moon position data
     */
    MoonPosition getCurrentPosition() const;
    
    /**
     * Get moon position at specific time
     * @param timestamp Time point for calculation
     * @return Moon position at specified time
     */
    MoonPosition getPositionAt(std::chrono::system_clock::time_point timestamp) const;
    
    /**
     * Update moon position (call periodically)
     * @param timestamp Current time (defaults to now)
     */
    void updatePosition(std::chrono::system_clock::time_point timestamp = std::chrono::system_clock::now());
    
    // Libration calculations
    
    /**
     * Calculate longitude libration
     * @param julian_day Julian day number
     * @return Longitude libration in degrees
     */
    double calculateLongitudeLibration(double julian_day) const;
    
    /**
     * Calculate latitude libration
     * @param julian_day Julian day number
     * @return Latitude libration in degrees
     */
    double calculateLatitudeLibration(double julian_day) const;
    
    /**
     * Get libration effects on distance
     * @param base_distance Base orbital distance
     * @return Additional distance variation due to libration
     */
    double getLibrationDistanceEffect(double base_distance) const;
    
    // EME communication calculations
    
    /**
     * Calculate round-trip delay
     * @param distance_km Distance to moon in kilometers
     * @return Round-trip delay in seconds
     */
    double calculateRoundTripDelay(double distance_km) const;
    
    /**
     * Calculate Doppler shift
     * @param frequency_mhz Operating frequency
     * @param radial_velocity_km_s Moon's radial velocity
     * @return Doppler shift in Hz
     */
    double calculateDopplerShift(double frequency_mhz, double radial_velocity_km_s) const;
    
    /**
     * Calculate EME path loss
     * @param distance_km Distance to moon
     * @param frequency_mhz Operating frequency
     * @return Path loss in dB
     */
    double calculateEMEPathLoss(double distance_km, double frequency_mhz) const;
    
    /**
     * Calculate complete EME parameters
     * @param frequency_mhz Operating frequency
     * @param transmit_power_watts Transmit power
     * @param antenna_gain_dbi Antenna gain
     * @return Complete EME parameters
     */
    EMEParameters calculateEMEParameters(double frequency_mhz, 
                                        double transmit_power_watts, 
                                        double antenna_gain_dbi) const;
    
    /**
     * Calculate EME parameters for specific band
     * @param band_name Band name (2m, 6m, 70cm, etc.)
     * @param transmit_power_watts Transmit power
     * @param antenna_gain_dbi Antenna gain
     * @return Complete EME parameters for band
     */
    EMEParameters calculateEMEParametersForBand(const std::string& band_name,
                                              double transmit_power_watts,
                                              double antenna_gain_dbi) const;
    
    /**
     * Get supported EME bands
     * @return Vector of supported band specifications
     */
    std::vector<EMEBandSpec> getSupportedEMEBands() const;
    
    /**
     * Check if frequency is supported for EME
     * @param frequency_mhz Operating frequency
     * @return True if frequency is supported
     */
    bool isFrequencySupported(double frequency_mhz) const;
    
    /**
     * Get band specification for frequency
     * @param frequency_mhz Operating frequency
     * @return Band specification or empty if not supported
     */
    EMEBandSpec getBandSpec(double frequency_mhz) const;
    
    // Manual override capabilities
    
    /**
     * Set manual moon position override
     * @param position Manual position data
     * @param enabled Enable/disable override
     */
    void setManualOverride(const MoonPosition& position, bool enabled = true);
    
    /**
     * Clear manual override
     */
    void clearManualOverride();
    
    /**
     * Check if manual override is active
     * @return True if manual override is active
     */
    bool isManualOverrideActive() const;
    
    /**
     * Set manual distance override
     * @param distance_km Manual distance in kilometers
     * @param enabled Enable/disable override
     */
    void setManualDistance(double distance_km, bool enabled = true);
    
    /**
     * Set manual delay override
     * @param delay_seconds Manual delay in seconds
     * @param enabled Enable/disable override
     */
    void setManualDelay(double delay_seconds, bool enabled = true);
    
    // Orbital mechanics calculations
    
    /**
     * Calculate moon distance at specific orbital position
     * @param orbital_phase Orbital phase (0-1, where 0=perigee, 0.5=apogee)
     * @return Distance in kilometers
     */
    double calculateOrbitalDistance(double orbital_phase) const;
    
    /**
     * Get orbital phase from distance
     * @param distance_km Distance in kilometers
     * @return Orbital phase (0-1)
     */
    double getOrbitalPhase(double distance_km) const;
    
    /**
     * Calculate moon's radial velocity
     * @param distance_km Current distance
     * @return Radial velocity in km/s
     */
    double calculateRadialVelocity(double distance_km) const;
    
    // Prediction and forecasting
    
    /**
     * Get next perigee time
     * @return Time of next perigee
     */
    std::chrono::system_clock::time_point getNextPerigee() const;
    
    /**
     * Get next apogee time
     * @return Time of next apogee
     */
    std::chrono::system_clock::time_point getNextApogee() const;
    
    /**
     * Get optimal EME windows (next 30 days)
     * @return Vector of optimal time windows
     */
    std::vector<std::pair<std::chrono::system_clock::time_point, 
                          std::chrono::system_clock::time_point>> getOptimalEMEWindows() const;
    
    /**
     * Predict moon position at future time
     * @param future_time Future time point
     * @return Predicted position
     */
    MoonPosition predictPosition(std::chrono::system_clock::time_point future_time) const;
    
    // Configuration and settings
    
    /**
     * Set calculation method
     * @param method Calculation method to use
     */
    void setCalculationMethod(MoonCalculationMethod method);
    
    /**
     * Get current calculation method
     * @return Current calculation method
     */
    MoonCalculationMethod getCalculationMethod() const;
    
    /**
     * Set update interval
     * @param interval_seconds Update interval in seconds
     */
    void setUpdateInterval(double interval_seconds);
    
    /**
     * Get current update interval
     * @return Update interval in seconds
     */
    double getUpdateInterval() const;
    
    // Utility functions
    
    /**
     * Convert Julian day to system time
     * @param julian_day Julian day number
     * @return System time point
     */
    static std::chrono::system_clock::time_point julianDayToTime(double julian_day);
    
    /**
     * Convert system time to Julian day
     * @param time_point System time point
     * @return Julian day number
     */
    static double timeToJulianDay(std::chrono::system_clock::time_point time_point);
    
    /**
     * Get moon phase name
     * @param phase_angle Phase angle in degrees
     * @return Phase name string
     */
    static std::string getMoonPhaseName(double phase_angle);
    
    /**
     * Format position data as string
     * @param position Moon position data
     * @return Formatted string
     */
    static std::string formatPosition(const MoonPosition& position);

private:
    MoonCalculationMethod calculation_method_;
    double update_interval_seconds_;
    std::chrono::system_clock::time_point last_update_;
    MoonPosition current_position_;
    
    // Manual override data
    bool manual_override_enabled_;
    MoonPosition manual_position_;
    bool manual_distance_override_;
    double manual_distance_km_;
    bool manual_delay_override_;
    double manual_delay_seconds_;
    
    // Internal calculation methods
    double calculateOrbitalDistance_(double julian_day) const;
    double calculateRightAscension_(double julian_day) const;
    double calculateDeclination_(double julian_day) const;
    double calculatePhaseAngle_(double julian_day) const;
    double calculateIllumination_(double phase_angle) const;
    double calculateRadialVelocity_(double julian_day) const;
    
    // Frequency-dependent calculations
    double calculateMoonReflectionLoss(double frequency_mhz) const;
    double calculateAtmosphericLoss(double frequency_mhz) const;
    EMEBandSpec getBandSpecByName(const std::string& band_name) const;
    
    // Libration calculations
    double calculateLibrationDistance_(double julian_day) const;
    double calculateLongitudeLibration_(double julian_day) const;
    double calculateLatitudeLibration_(double julian_day) const;
    
    // EME calculations
    double calculateEMEPathLoss_(double distance_km, double frequency_mhz) const;
    double calculateDopplerShift_(double frequency_mhz, double radial_velocity) const;
    double calculateRoundTripDelay_(double distance_km) const;
    
    // Orbital mechanics constants
    static constexpr double MOON_ORBITAL_PERIOD_DAYS = 27.321661;
    static constexpr double MOON_PERIGEE_DISTANCE_KM = 356400.0;
    static constexpr double MOON_APOGEE_DISTANCE_KM = 406700.0;
    static constexpr double MOON_AVERAGE_DISTANCE_KM = 384400.0;
    static constexpr double SPEED_OF_LIGHT_KM_S = 299792.458;
    static constexpr double LIGHT_SPEED_M_S = 299792458.0;
    
    // Libration constants
    static constexpr double MAX_LONGITUDE_LIBRATION_DEG = 7.9;
    static constexpr double MAX_LATITUDE_LIBRATION_DEG = 6.7;
    static constexpr double LIBRATION_DISTANCE_EFFECT_KM = 1700.0;
};

} // namespace FGCom

#endif // MOON_POSITION_TRACKER_H
