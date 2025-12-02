/**
 * Moon Position Tracking API Implementation
 * 
 * Comprehensive moon position tracking for EME communication
 */

#include "space/moon/moon_position_tracker.h"
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace FGCom {

MoonPositionTracker::MoonPositionTracker(MoonCalculationMethod calculation_method)
    : calculation_method_(calculation_method)
    , update_interval_seconds_(60.0)  // Update every minute
    , last_update_(std::chrono::system_clock::now())
    , manual_override_enabled_(false)
    , manual_distance_override_(false)
    , manual_distance_km_(384400.0)
    , manual_delay_override_(false)
    , manual_delay_seconds_(2.565)
{
    updatePosition();
}

MoonPosition MoonPositionTracker::getCurrentPosition() const {
    return current_position_;
}

MoonPosition MoonPositionTracker::getPositionAt(std::chrono::system_clock::time_point timestamp) const {
    if (manual_override_enabled_) {
        return manual_position_;
    }
    
    double julian_day = timeToJulianDay(timestamp);
    MoonPosition position;
    
    position.distance_km = calculateOrbitalDistance_(julian_day);
    position.right_ascension_deg = calculateRightAscension_(julian_day);
    position.declination_deg = calculateDeclination_(julian_day);
    position.longitude_libration_deg = calculateLongitudeLibration_(julian_day);
    position.latitude_libration_deg = calculateLatitudeLibration_(julian_day);
    position.phase_angle_deg = calculatePhaseAngle_(julian_day);
    position.illumination_percent = calculateIllumination_(position.phase_angle_deg);
    position.timestamp = timestamp;
    
    // Calculate derived values
    position.round_trip_delay_seconds = calculateRoundTripDelay_(position.distance_km);
    position.doppler_shift_hz = calculateDopplerShift_(144.0, calculateRadialVelocity_(julian_day));
    position.path_loss_db = calculateEMEPathLoss_(position.distance_km, 144.0);
    position.libration_distance_km = calculateLibrationDistance_(julian_day);
    
    return position;
}

void MoonPositionTracker::updatePosition(std::chrono::system_clock::time_point timestamp) {
    current_position_ = getPositionAt(timestamp);
    last_update_ = timestamp;
}

double MoonPositionTracker::calculateLongitudeLibration(double julian_day) const {
    return calculateLongitudeLibration_(julian_day);
}

double MoonPositionTracker::calculateLatitudeLibration(double julian_day) const {
    return calculateLatitudeLibration_(julian_day);
}

double MoonPositionTracker::getLibrationDistanceEffect(double base_distance) const {
    return calculateLibrationDistance_(timeToJulianDay(std::chrono::system_clock::now()));
}

double MoonPositionTracker::calculateRoundTripDelay(double distance_km) const {
    return calculateRoundTripDelay_(distance_km);
}

double MoonPositionTracker::calculateDopplerShift(double frequency_mhz, double radial_velocity_km_s) const {
    return calculateDopplerShift_(frequency_mhz, radial_velocity_km_s);
}

double MoonPositionTracker::calculateEMEPathLoss(double distance_km, double frequency_mhz) const {
    return calculateEMEPathLoss_(distance_km, frequency_mhz);
}

EMEParameters MoonPositionTracker::calculateEMEParameters(double frequency_mhz, 
                                                        double transmit_power_watts, 
                                                        double antenna_gain_dbi) const {
    EMEParameters params;
    
    params.frequency_mhz = frequency_mhz;
    params.transmit_power_watts = transmit_power_watts;
    params.antenna_gain_dbi = antenna_gain_dbi;
    params.system_noise_temp_k = 300.0;  // Typical system temperature
    params.bandwidth_hz = 500.0;  // CW bandwidth
    
    // Calculate wavelength
    params.wavelength_m = LIGHT_SPEED_M_S / (frequency_mhz * 1e6);
    
    // Calculate ERP
    double power_dbw = 10.0 * std::log10(transmit_power_watts);
    params.effective_radiated_power_dbw = power_dbw + antenna_gain_dbi;
    
    // Get current moon position
    MoonPosition moon_pos = getCurrentPosition();
    
    // Calculate path loss
    params.path_loss_db = calculateEMEPathLoss_(moon_pos.distance_km, frequency_mhz);
    
    // Moon reflection loss (frequency dependent)
    params.moon_reflection_loss_db = calculateMoonReflectionLoss(frequency_mhz);
    
    // Atmospheric loss (frequency dependent)
    params.atmospheric_loss_db = calculateAtmosphericLoss(frequency_mhz);
    
    // Total path loss (round trip)
    double total_path_loss = 2.0 * params.path_loss_db + params.moon_reflection_loss_db + params.atmospheric_loss_db;
    
    // Received power
    params.received_power_dbw = params.effective_radiated_power_dbw - total_path_loss + antenna_gain_dbi;
    
    // Calculate noise floor
    double boltzmann_constant = 1.38e-23;
    double noise_power_watts = boltzmann_constant * params.system_noise_temp_k * params.bandwidth_hz;
    double noise_power_dbw = 10.0 * std::log10(noise_power_watts);
    
    // Signal-to-noise ratio
    params.signal_to_noise_ratio_db = params.received_power_dbw - noise_power_dbw;
    
    // Communication range (simplified)
    params.communication_range_km = moon_pos.distance_km;
    
    return params;
}

// Helper methods for frequency-dependent calculations
double MoonPositionTracker::calculateMoonReflectionLoss(double frequency_mhz) const {
    // Moon reflection loss is frequency dependent
    // Lower frequencies have better reflection characteristics
    if (frequency_mhz < 100.0) {
        return 4.0;  // 6m band - better reflection
    } else if (frequency_mhz < 200.0) {
        return 6.0;  // 2m band - typical reflection
    } else if (frequency_mhz < 500.0) {
        return 8.0;  // 70cm band - worse reflection
    } else {
        return 10.0; // Higher frequencies - poor reflection
    }
}

double MoonPositionTracker::calculateAtmosphericLoss(double frequency_mhz) const {
    // Atmospheric loss is frequency dependent
    // Higher frequencies have more atmospheric absorption
    if (frequency_mhz < 100.0) {
        return 0.1;  // 6m band - minimal atmospheric loss
    } else if (frequency_mhz < 200.0) {
        return 0.5;  // 2m band - minimal atmospheric loss
    } else if (frequency_mhz < 500.0) {
        return 1.0;  // 70cm band - some atmospheric loss
    } else {
        return 2.0;  // Higher frequencies - significant atmospheric loss
    }
}

EMEBandSpec MoonPositionTracker::getBandSpecByName(const std::string& band_name) const {
    auto bands = getSupportedEMEBands();
    for (const auto& band : bands) {
        if (band.name == band_name) {
            return band;
        }
    }
    return EMEBandSpec{};  // Empty spec for unknown band
}

EMEParameters MoonPositionTracker::calculateEMEParametersForBand(const std::string& band_name,
                                                              double transmit_power_watts,
                                                              double antenna_gain_dbi) const {
    // Get band specification
    EMEBandSpec band_spec = getBandSpecByName(band_name);
    if (!band_spec.is_supported) {
        // Return empty parameters for unsupported band
        return EMEParameters{};
    }
    
    return calculateEMEParameters(band_spec.frequency_mhz, transmit_power_watts, antenna_gain_dbi);
}

std::vector<EMEBandSpec> MoonPositionTracker::getSupportedEMEBands() const {
    std::vector<EMEBandSpec> bands;
    
    // 2m band (144 MHz)
    bands.push_back({"2m", 144.0, 2.083, 2.0, 14.8, 300.0, true});
    
    // 6m band (50 MHz)
    bands.push_back({"6m", 50.0, 6.0, 4.0, 12.0, 200.0, true});
    
    // 70cm band (432 MHz)
    bands.push_back({"70cm", 432.0, 0.694, 2.0, 16.5, 400.0, true});
    
    // 23cm band (1296 MHz)
    bands.push_back({"23cm", 1296.0, 0.231, 1.0, 20.0, 500.0, true});
    
    // 13cm band (2304 MHz)
    bands.push_back({"13cm", 2304.0, 0.130, 0.5, 22.0, 600.0, true});
    
    // 9cm band (3456 MHz)
    bands.push_back({"9cm", 3456.0, 0.087, 0.2, 24.0, 700.0, true});
    
    // 6cm band (5760 MHz)
    bands.push_back({"6cm", 5760.0, 0.052, 0.1, 26.0, 800.0, true});
    
    // 3cm band (10368 MHz)
    bands.push_back({"3cm", 10368.0, 0.029, 0.05, 28.0, 900.0, true});
    
    return bands;
}

bool MoonPositionTracker::isFrequencySupported(double frequency_mhz) const {
    auto bands = getSupportedEMEBands();
    for (const auto& band : bands) {
        if (std::abs(frequency_mhz - band.frequency_mhz) <= band.bandwidth_mhz / 2.0) {
            return band.is_supported;
        }
    }
    return false;
}

EMEBandSpec MoonPositionTracker::getBandSpec(double frequency_mhz) const {
    auto bands = getSupportedEMEBands();
    for (const auto& band : bands) {
        if (std::abs(frequency_mhz - band.frequency_mhz) <= band.bandwidth_mhz / 2.0) {
            return band;
        }
    }
    return EMEBandSpec{};  // Empty spec for unsupported frequency
}

void MoonPositionTracker::setManualOverride(const MoonPosition& position, bool enabled) {
    manual_position_ = position;
    manual_override_enabled_ = enabled;
}

void MoonPositionTracker::clearManualOverride() {
    manual_override_enabled_ = false;
    manual_distance_override_ = false;
    manual_delay_override_ = false;
}

bool MoonPositionTracker::isManualOverrideActive() const {
    return manual_override_enabled_;
}

void MoonPositionTracker::setManualDistance(double distance_km, bool enabled) {
    manual_distance_km_ = distance_km;
    manual_distance_override_ = enabled;
}

void MoonPositionTracker::setManualDelay(double delay_seconds, bool enabled) {
    manual_delay_seconds_ = delay_seconds;
    manual_delay_override_ = enabled;
}

double MoonPositionTracker::calculateOrbitalDistance(double orbital_phase) const {
    // Simplified elliptical orbit calculation
    double eccentricity = 0.0549;  // Moon's orbital eccentricity
    double semi_major_axis = MOON_AVERAGE_DISTANCE_KM;
    
    // Distance at given orbital phase
    double true_anomaly = orbital_phase * 2.0 * M_PI;
    double distance = semi_major_axis * (1.0 - eccentricity * eccentricity) / 
                      (1.0 + eccentricity * std::cos(true_anomaly));
    
    return distance;
}

double MoonPositionTracker::getOrbitalPhase(double distance_km) const {
    // Reverse calculation of orbital phase from distance
    double eccentricity = 0.0549;
    double semi_major_axis = MOON_AVERAGE_DISTANCE_KM;
    
    double cos_true_anomaly = ((semi_major_axis * (1.0 - eccentricity * eccentricity)) / distance_km - 1.0) / eccentricity;
    cos_true_anomaly = std::max(-1.0, std::min(1.0, cos_true_anomaly));  // Clamp to valid range
    
    double true_anomaly = std::acos(cos_true_anomaly);
    return true_anomaly / (2.0 * M_PI);
}

double MoonPositionTracker::calculateRadialVelocity(double distance_km) const {
    // Simplified radial velocity calculation
    double orbital_phase = getOrbitalPhase(distance_km);
    double orbital_velocity = 2.0 * M_PI * MOON_AVERAGE_DISTANCE_KM / (MOON_ORBITAL_PERIOD_DAYS * 24.0 * 3600.0);
    
    // Radial component of velocity
    double radial_velocity = orbital_velocity * std::sin(2.0 * M_PI * orbital_phase);
    
    return radial_velocity;
}

std::chrono::system_clock::time_point MoonPositionTracker::getNextPerigee() const {
    // Simplified calculation - in practice would use more sophisticated orbital mechanics
    auto now = std::chrono::system_clock::now();
    double julian_day = timeToJulianDay(now);
    
    // Find next perigee (simplified)
    double days_since_perigee = std::fmod(julian_day, MOON_ORBITAL_PERIOD_DAYS);
    double days_to_next_perigee = MOON_ORBITAL_PERIOD_DAYS - days_since_perigee;
    
    return now + std::chrono::duration_cast<std::chrono::system_clock::duration>(
        std::chrono::duration<double>(days_to_next_perigee * 24.0 * 3600.0));
}

std::chrono::system_clock::time_point MoonPositionTracker::getNextApogee() const {
    auto now = std::chrono::system_clock::now();
    double julian_day = timeToJulianDay(now);
    
    // Find next apogee (simplified)
    double days_since_apogee = std::fmod(julian_day + MOON_ORBITAL_PERIOD_DAYS / 2.0, MOON_ORBITAL_PERIOD_DAYS);
    double days_to_next_apogee = MOON_ORBITAL_PERIOD_DAYS - days_since_apogee;
    
    return now + std::chrono::duration_cast<std::chrono::system_clock::duration>(
        std::chrono::duration<double>(days_to_next_apogee * 24.0 * 3600.0));
}

std::vector<std::pair<std::chrono::system_clock::time_point, 
                      std::chrono::system_clock::time_point>> MoonPositionTracker::getOptimalEMEWindows() const {
    std::vector<std::pair<std::chrono::system_clock::time_point, 
                          std::chrono::system_clock::time_point>> windows;
    
    // Simplified: optimal windows are near perigee
    auto next_perigee = getNextPerigee();
    
    // Create 30-day window starting from next perigee
    for (int day = 0; day < 30; ++day) {
        auto window_start = next_perigee + std::chrono::hours(24 * day);
        auto window_end = window_start + std::chrono::hours(6);  // 6-hour optimal window
        
        windows.emplace_back(window_start, window_end);
    }
    
    return windows;
}

MoonPosition MoonPositionTracker::predictPosition(std::chrono::system_clock::time_point future_time) const {
    return getPositionAt(future_time);
}

void MoonPositionTracker::setCalculationMethod(MoonCalculationMethod method) {
    calculation_method_ = method;
}

MoonCalculationMethod MoonPositionTracker::getCalculationMethod() const {
    return calculation_method_;
}

void MoonPositionTracker::setUpdateInterval(double interval_seconds) {
    update_interval_seconds_ = interval_seconds;
}

double MoonPositionTracker::getUpdateInterval() const {
    return update_interval_seconds_;
}

std::chrono::system_clock::time_point MoonPositionTracker::julianDayToTime(double julian_day) {
    // Simplified conversion - in practice would use proper astronomical calculations
    constexpr double JULIAN_DAY_EPOCH = 2440587.5;  // Unix epoch in Julian days
    constexpr double SECONDS_PER_DAY = 86400.0;
    
    double unix_timestamp = (julian_day - JULIAN_DAY_EPOCH) * SECONDS_PER_DAY;
    return std::chrono::system_clock::from_time_t(static_cast<std::time_t>(unix_timestamp));
}

double MoonPositionTracker::timeToJulianDay(std::chrono::system_clock::time_point time_point) {
    constexpr double JULIAN_DAY_EPOCH = 2440587.5;
    constexpr double SECONDS_PER_DAY = 86400.0;
    
    auto unix_timestamp = std::chrono::system_clock::to_time_t(time_point);
    return JULIAN_DAY_EPOCH + static_cast<double>(unix_timestamp) / SECONDS_PER_DAY;
}

std::string MoonPositionTracker::getMoonPhaseName(double phase_angle) {
    if (phase_angle < 22.5 || phase_angle >= 337.5) return "New Moon";
    if (phase_angle < 67.5) return "Waxing Crescent";
    if (phase_angle < 112.5) return "First Quarter";
    if (phase_angle < 157.5) return "Waxing Gibbous";
    if (phase_angle < 202.5) return "Full Moon";
    if (phase_angle < 247.5) return "Waning Gibbous";
    if (phase_angle < 292.5) return "Last Quarter";
    return "Waning Crescent";
}

std::string MoonPositionTracker::formatPosition(const MoonPosition& position) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    oss << "Moon Position:\n";
    oss << "  Distance: " << position.distance_km << " km\n";
    oss << "  RA: " << position.right_ascension_deg << "°\n";
    oss << "  Dec: " << position.declination_deg << "°\n";
    oss << "  Libration (Lon/Lat): " << position.longitude_libration_deg << "° / " 
        << position.latitude_libration_deg << "°\n";
    oss << "  Round-trip delay: " << position.round_trip_delay_seconds << " s\n";
    oss << "  Doppler shift: " << position.doppler_shift_hz << " Hz\n";
    oss << "  Path loss: " << position.path_loss_db << " dB\n";
    oss << "  Phase: " << getMoonPhaseName(position.phase_angle_deg) 
        << " (" << position.illumination_percent << "%)\n";
    
    return oss.str();
}

// Private implementation methods

double MoonPositionTracker::calculateOrbitalDistance_(double julian_day) const {
    if (manual_distance_override_) {
        return manual_distance_km_;
    }
    
    // Simplified orbital distance calculation
    double orbital_phase = std::fmod(julian_day, MOON_ORBITAL_PERIOD_DAYS) / MOON_ORBITAL_PERIOD_DAYS;
    return calculateOrbitalDistance(orbital_phase);
}

double MoonPositionTracker::calculateRightAscension_(double julian_day) const {
    // Simplified RA calculation
    double orbital_phase = std::fmod(julian_day, MOON_ORBITAL_PERIOD_DAYS) / MOON_ORBITAL_PERIOD_DAYS;
    return orbital_phase * 360.0;  // Simplified - would use proper astronomical calculations
}

double MoonPositionTracker::calculateDeclination_(double julian_day) const {
    // Simplified declination calculation
    double orbital_phase = std::fmod(julian_day, MOON_ORBITAL_PERIOD_DAYS) / MOON_ORBITAL_PERIOD_DAYS;
    return 28.5 * std::sin(2.0 * M_PI * orbital_phase);  // ±28.5° declination range
}

double MoonPositionTracker::calculatePhaseAngle_(double julian_day) const {
    // Simplified phase angle calculation
    double orbital_phase = std::fmod(julian_day, MOON_ORBITAL_PERIOD_DAYS) / MOON_ORBITAL_PERIOD_DAYS;
    return orbital_phase * 360.0;
}

double MoonPositionTracker::calculateIllumination_(double phase_angle) const {
    // Simplified illumination calculation
    double phase_rad = phase_angle * M_PI / 180.0;
    return 50.0 * (1.0 + std::cos(phase_rad));
}

double MoonPositionTracker::calculateRadialVelocity_(double julian_day) const {
    double orbital_phase = std::fmod(julian_day, MOON_ORBITAL_PERIOD_DAYS) / MOON_ORBITAL_PERIOD_DAYS;
    double orbital_velocity = 2.0 * M_PI * MOON_AVERAGE_DISTANCE_KM / (MOON_ORBITAL_PERIOD_DAYS * 24.0 * 3600.0);
    return orbital_velocity * std::sin(2.0 * M_PI * orbital_phase);
}

double MoonPositionTracker::calculateLibrationDistance_(double julian_day) const {
    double longitude_lib = calculateLongitudeLibration_(julian_day);
    double latitude_lib = calculateLatitudeLibration_(julian_day);
    
    // Libration distance effect (simplified)
    double libration_factor = std::sqrt(longitude_lib * longitude_lib + latitude_lib * latitude_lib) / 
                             std::sqrt(MAX_LONGITUDE_LIBRATION_DEG * MAX_LONGITUDE_LIBRATION_DEG + 
                                      MAX_LATITUDE_LIBRATION_DEG * MAX_LATITUDE_LIBRATION_DEG);
    
    return LIBRATION_DISTANCE_EFFECT_KM * libration_factor;
}

double MoonPositionTracker::calculateLongitudeLibration_(double julian_day) const {
    // Simplified longitude libration calculation
    double orbital_phase = std::fmod(julian_day, MOON_ORBITAL_PERIOD_DAYS) / MOON_ORBITAL_PERIOD_DAYS;
    return MAX_LONGITUDE_LIBRATION_DEG * std::sin(2.0 * M_PI * orbital_phase);
}

double MoonPositionTracker::calculateLatitudeLibration_(double julian_day) const {
    // Simplified latitude libration calculation
    double orbital_phase = std::fmod(julian_day, MOON_ORBITAL_PERIOD_DAYS) / MOON_ORBITAL_PERIOD_DAYS;
    return MAX_LATITUDE_LIBRATION_DEG * std::cos(2.0 * M_PI * orbital_phase);
}

double MoonPositionTracker::calculateEMEPathLoss_(double distance_km, double frequency_mhz) const {
    double wavelength_m = LIGHT_SPEED_M_S / (frequency_mhz * 1e6);
    return 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / wavelength_m);
}

double MoonPositionTracker::calculateDopplerShift_(double frequency_mhz, double radial_velocity) const {
    return frequency_mhz * 1e6 * (radial_velocity * 1000.0 / LIGHT_SPEED_M_S);
}

double MoonPositionTracker::calculateRoundTripDelay_(double distance_km) const {
    if (manual_delay_override_) {
        return manual_delay_seconds_;
    }
    
    return (2.0 * distance_km * 1000.0) / LIGHT_SPEED_M_S;
}

} // namespace FGCom
