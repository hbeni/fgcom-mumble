#include "terrain_environmental_api.h"
#include "terrain_exceptions.h"
#include "terrain_state_machine.h"
#include "terrain_data_access.h"
#include "terrain_cache.h"
#include "terrain_statistics.h"
#include <stdexcept>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>

namespace FGCom_TerrainEnvironmental {

    // Coordinate implementation
    Coordinate::Coordinate(double latitude, double longitude, double altitude)
        : latitude_(latitude), longitude_(longitude), altitude_(altitude) {
        validateCoordinates(latitude, longitude, altitude);
    }

    double Coordinate::getLatitude() const noexcept {
        return latitude_;
    }

    double Coordinate::getLongitude() const noexcept {
        return longitude_;
    }

    double Coordinate::getAltitude() const noexcept {
        return altitude_;
    }

    bool Coordinate::isValid() const noexcept {
        return latitude_ >= MIN_LATITUDE && latitude_ <= MAX_LATITUDE &&
               longitude_ >= MIN_LONGITUDE && longitude_ <= MAX_LONGITUDE &&
               altitude_ >= MIN_ALTITUDE && altitude_ <= MAX_ALTITUDE;
    }

    double Coordinate::calculateDistance(const Coordinate& other) const {
        if (!isValid() || !other.isValid()) {
            throw InvalidCoordinateException("Invalid coordinates for distance calculation");
        }
        
        // Haversine formula for great circle distance
        const double R = 6371000.0; // Earth radius in meters
        const double lat1_rad = latitude_ * M_PI / 180.0;
        const double lat2_rad = other.latitude_ * M_PI / 180.0;
        const double delta_lat = (other.latitude_ - latitude_) * M_PI / 180.0;
        const double delta_lon = (other.longitude_ - longitude_) * M_PI / 180.0;
        
        const double a = std::sin(delta_lat / 2.0) * std::sin(delta_lat / 2.0) +
                        std::cos(lat1_rad) * std::cos(lat2_rad) *
                        std::sin(delta_lon / 2.0) * std::sin(delta_lon / 2.0);
        const double c = 2.0 * std::atan2(std::sqrt(a), std::sqrt(1.0 - a));
        
        return R * c;
    }

    std::string Coordinate::toString() const {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(6);
        oss << "(" << latitude_ << ", " << longitude_ << ", " << altitude_ << ")";
        return oss.str();
    }

    void Coordinate::validateCoordinates(double lat, double lon, double alt) const {
        if (lat < MIN_LATITUDE || lat > MAX_LATITUDE) {
            throw InvalidCoordinateException("Latitude out of range: " + std::to_string(lat));
        }
        if (lon < MIN_LONGITUDE || lon > MAX_LONGITUDE) {
            throw InvalidCoordinateException("Longitude out of range: " + std::to_string(lon));
        }
        if (alt < MIN_ALTITUDE || alt > MAX_ALTITUDE) {
            throw InvalidCoordinateException("Altitude out of range: " + std::to_string(alt));
        }
        if (!std::isfinite(lat) || !std::isfinite(lon) || !std::isfinite(alt)) {
            throw InvalidCoordinateException("Non-finite coordinate values");
        }
    }

    // LineOfSightData implementation
    LineOfSightData::LineOfSightData() noexcept
        : line_of_sight_blocked(false), obstruction_distance(0.0), 
          obstruction_height(0.0), clearance_angle(0.0) {
    }

    bool LineOfSightData::isValid() const noexcept {
        return obstruction_distance >= 0.0 && obstruction_height >= 0.0 &&
               clearance_angle >= -90.0 && clearance_angle <= 90.0;
    }

    // TerrainAltitudeData implementation
    TerrainAltitudeData::TerrainAltitudeData() noexcept
        : ground_altitude(0.0), terrain_type("unknown"), surface_material("unknown") {
    }

    bool TerrainAltitudeData::isValid() const noexcept {
        return ground_altitude >= -500.0 && ground_altitude <= 10000.0 &&
               !terrain_type.empty() && !surface_material.empty();
    }

    // NoiseFloorData implementation
    NoiseFloorData::NoiseFloorData() noexcept
        : ambient_noise_level(-120.0), atmospheric_noise(-115.0), man_made_noise(-110.0),
          total_noise_floor(-108.0), environment_type("rural") {
    }

    bool NoiseFloorData::isValid() const noexcept {
        return ambient_noise_level >= -200.0 && ambient_noise_level <= 0.0 &&
               atmospheric_noise >= -200.0 && atmospheric_noise <= 0.0 &&
               man_made_noise >= -200.0 && man_made_noise <= 0.0 &&
               total_noise_floor >= -200.0 && total_noise_floor <= 0.0 &&
               !environment_type.empty();
    }

    // TerrainDataProvider implementation
    TerrainDataProvider::TerrainDataProvider(std::unique_ptr<TerrainDataAccess> dataAccess,
                                           std::unique_ptr<TerrainCache> cache,
                                           std::unique_ptr<TerrainStatistics> statistics)
        : data_access_(std::move(dataAccess)),
          cache_(std::move(cache)),
          statistics_(std::move(statistics)),
          state_machine_(std::make_unique<TerrainStateMachine>()) {
        
        if (!data_access_) {
            throw ConfigurationException("TerrainDataAccess cannot be null");
        }
        
        // Initialize default components if not provided
        if (!cache_) {
            cache_ = std::make_unique<TerrainCache>();
        }
        if (!statistics_) {
            statistics_ = std::make_unique<TerrainStatistics>();
        }
    }

    TerrainDataProvider::~TerrainDataProvider() = default;

    TerrainDataProvider::TerrainDataProvider(TerrainDataProvider&& other) noexcept
        : data_access_(std::move(other.data_access_)),
          cache_(std::move(other.cache_)),
          statistics_(std::move(other.statistics_)),
          state_machine_(std::move(other.state_machine_)) {
    }

    TerrainDataProvider& TerrainDataProvider::operator=(TerrainDataProvider&& other) noexcept {
        if (this != &other) {
            data_access_ = std::move(other.data_access_);
            cache_ = std::move(other.cache_);
            statistics_ = std::move(other.statistics_);
            state_machine_ = std::move(other.state_machine_);
        }
        return *this;
    }

    LineOfSightData TerrainDataProvider::checkLineOfSight(const Coordinate& transmitter, 
                                                       const Coordinate& receiver) {
        if (!validateCoordinate(transmitter) || !validateCoordinate(receiver)) {
            throw InvalidCoordinateException("Invalid transmitter or receiver coordinates");
        }
        
        if (!state_machine_->canPerformOperations()) {
            throw TerrainDataException("Terrain provider not ready for operations");
        }
        
        TerrainOperationRecorder recorder(*statistics_, "los_check");
        
        try {
            std::lock_guard<std::mutex> lock(operation_mutex_);
            
            LineOfSightData result;
            
            // Calculate distance between points
            double distance = transmitter.calculateDistance(receiver);
            
            // Get terrain heights using data access layer
            double tx_height = data_access_->getTerrainHeight(transmitter.getLatitude(), 
                                                           transmitter.getLongitude());
            double rx_height = data_access_->getTerrainHeight(receiver.getLatitude(), 
                                                           receiver.getLongitude());
            
            // Check if line of sight is blocked by terrain
            result.line_of_sight_blocked = (tx_height > transmitter.getAltitude() ||
                                           rx_height > receiver.getAltitude());
            result.obstruction_distance = result.line_of_sight_blocked ? distance / 2.0 : 0.0;
            result.obstruction_height = std::max(tx_height, rx_height);
            
            // Calculate clearance angle
            double altitude_diff = receiver.getAltitude() - transmitter.getAltitude();
            result.clearance_angle = std::atan2(altitude_diff, distance) * 180.0 / M_PI;
            
            // Generate terrain profile
            result.terrain_profile.clear();
            for (int i = 0; i <= 10; ++i) {
                double fraction = static_cast<double>(i) / 10.0;
                double lat = transmitter.getLatitude() + 
                           (receiver.getLatitude() - transmitter.getLatitude()) * fraction;
                double lon = transmitter.getLongitude() + 
                           (receiver.getLongitude() - transmitter.getLongitude()) * fraction;
                
                double terrain_height = data_access_->getTerrainHeight(lat, lon);
                result.terrain_profile.emplace_back(distance * fraction, terrain_height);
            }
            
            recorder.markSuccess();
            return result;
            
        } catch (const std::exception& e) {
            recorder.markFailure("los_calculation_error");
            throw CalculationException("Line of sight calculation failed: " + std::string(e.what()));
        }
    }

    TerrainAltitudeData TerrainDataProvider::getTerrainAltitude(const Coordinate& coordinate) {
        if (!validateCoordinate(coordinate)) {
            throw InvalidCoordinateException("Invalid coordinate for terrain altitude query");
        }
        
        if (!state_machine_->canPerformOperations()) {
            throw TerrainDataException("Terrain provider not ready for operations");
        }
        
        TerrainOperationRecorder recorder(*statistics_, "altitude_query");
        
        try {
            std::lock_guard<std::mutex> lock(operation_mutex_);
            
            TerrainAltitudeData result;
            
            // Get terrain height using data access layer
            double terrain_height = data_access_->getTerrainHeight(coordinate.getLatitude(), 
                                                                 coordinate.getLongitude());
            
            result.ground_altitude = terrain_height;
            result.terrain_type = "unknown"; // Would be determined by terrain analysis
            result.surface_material = "unknown"; // Would be determined by terrain analysis
            
            recorder.markSuccess();
            return result;
            
        } catch (const std::exception& e) {
            recorder.markFailure("altitude_query_error");
            throw TerrainDataException("Terrain altitude query failed: " + std::string(e.what()));
        }
    }

    EnvironmentalConditions TerrainDataProvider::getEnvironmentalConditions(const Coordinate& coordinate) {
        if (!validateCoordinate(coordinate)) {
            throw InvalidCoordinateException("Invalid coordinate for environmental query");
        }
        
        if (!state_machine_->canPerformOperations()) {
            throw TerrainDataException("Terrain provider not ready for operations");
        }
        
        TerrainOperationRecorder recorder(*statistics_, "environmental_query");
        
        try {
            std::lock_guard<std::mutex> lock(operation_mutex_);
            
            // Get environmental conditions using data access layer
            EnvironmentalConditions result = data_access_->getEnvironmentalConditions(
                coordinate.getLatitude(), coordinate.getLongitude());
            
            recorder.markSuccess();
            return result;
            
        } catch (const std::exception& e) {
            recorder.markFailure("environmental_query_error");
            throw EnvironmentalDataException("Environmental query failed: " + std::string(e.what()));
        }
    }

    NoiseFloorData TerrainDataProvider::calculateNoiseFloor(const Coordinate& coordinate, 
                                                          double frequency, 
                                                          const std::string& timeOfDay, 
                                                          const std::string& season) {
        if (!validateCoordinate(coordinate)) {
            throw InvalidCoordinateException("Invalid coordinate for noise floor calculation");
        }
        
        if (!validateFrequency(frequency)) {
            throw InvalidFrequencyException("Invalid frequency: " + std::to_string(frequency));
        }
        
        if (!state_machine_->canPerformOperations()) {
            throw TerrainDataException("Terrain provider not ready for operations");
        }
        
        TerrainOperationRecorder recorder(*statistics_, "noise_calculation");
        
        try {
            std::lock_guard<std::mutex> lock(operation_mutex_);
            
            NoiseFloorData result;
            
            // Get environmental conditions for noise calculation
            EnvironmentalConditions env = data_access_->getEnvironmentalConditions(
                coordinate.getLatitude(), coordinate.getLongitude());
            
            // Calculate atmospheric noise based on frequency and environmental conditions
            result.atmospheric_noise = calculateAtmosphericNoise(frequency, env);
            
            // Calculate man-made noise based on environment type
            result.man_made_noise = calculateManMadeNoise("urban"); // Simplified
            
            // Calculate ambient noise level
            result.ambient_noise_level = -120.0; // Base thermal noise
            
            // Calculate total noise floor
            result.total_noise_floor = std::max({result.ambient_noise_level, 
                                               result.atmospheric_noise, 
                                               result.man_made_noise});
            
            result.environment_type = "urban"; // Simplified
            
            recorder.markSuccess();
            return result;
            
        } catch (const std::exception& e) {
            recorder.markFailure("noise_calculation_error");
            throw CalculationException("Noise floor calculation failed: " + std::string(e.what()));
        }
    }

    std::string TerrainDataProvider::getPerformanceStats() const {
        return statistics_->getStatistics();
    }

    // Private helper methods
    bool TerrainDataProvider::validateCoordinate(const Coordinate& coord) const noexcept {
        return coord.isValid();
    }

    bool TerrainDataProvider::validateFrequency(double frequency) const noexcept {
        return frequency > 0.0 && frequency < 1000000000.0 && std::isfinite(frequency);
    }

    bool TerrainDataProvider::validateTimeOfDay(const std::string& timeOfDay) const noexcept {
        return timeOfDay == "day" || timeOfDay == "night";
    }

    bool TerrainDataProvider::validateSeason(const std::string& season) const noexcept {
        return season == "spring" || season == "summer" || season == "autumn" || season == "winter";
    }

    double TerrainDataProvider::calculateTerrainHeight(double latitude, double longitude) const {
        return data_access_->getTerrainHeight(latitude, longitude);
    }

    EnvironmentalConditions TerrainDataProvider::getEnvironmentalData(double latitude, double longitude) const {
        return data_access_->getEnvironmentalConditions(latitude, longitude);
    }

    double TerrainDataProvider::calculateAtmosphericNoise(double frequency, const EnvironmentalConditions& env) const {
        // Simplified atmospheric noise calculation
        double base_noise = -115.0;
        
        // Adjust for temperature
        if (env.temperature > 30.0) {
            base_noise += 2.0;
        } else if (env.temperature < 0.0) {
            base_noise -= 2.0;
        }
        
        // Adjust for humidity
        if (env.humidity > 80.0) {
            base_noise += 1.0;
        }
        
        // Adjust for precipitation
        if (env.precipitation_type != "none") {
            base_noise += env.precipitation_intensity * 5.0;
        }
        
        return base_noise;
    }

    double TerrainDataProvider::calculateManMadeNoise(const std::string& environmentType) const {
        if (environmentType == "urban") {
            return -90.0;
        } else if (environmentType == "suburban") {
            return -100.0;
        } else {
            return -110.0; // Rural
        }
    }

    std::string TerrainDataProvider::generateCacheKey(const std::string& operation, 
                                                     const Coordinate& coord1, 
                                                     const Coordinate& coord2) const {
        std::ostringstream oss;
        oss << operation << "_" << std::fixed << std::setprecision(6)
            << coord1.getLatitude() << "_" << coord1.getLongitude() << "_" << coord1.getAltitude();
        if (coord2.getLatitude() != 0.0 || coord2.getLongitude() != 0.0 || coord2.getAltitude() != 0.0) {
            oss << "_" << coord2.getLatitude() << "_" << coord2.getLongitude() << "_" << coord2.getAltitude();
        }
        return oss.str();
    }

    bool TerrainDataProvider::isCacheValid(const std::string& key) const {
        return cache_->exists(key);
    }

    void TerrainDataProvider::updateCache(const std::string& key, const std::string& data) {
        cache_->store(key, data);
    }

    std::string TerrainDataProvider::getCachedData(const std::string& key) {
        return cache_->retrieve(key);
    }

} // namespace FGCom_TerrainEnvironmental
