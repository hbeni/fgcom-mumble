#include "terrain_data_access.h"
#include "terrain_exceptions.h"
#include <stdexcept>
#include <cmath>

namespace FGCom_TerrainEnvironmental {

    // CallbackTerrainDataAccess implementation
    CallbackTerrainDataAccess::CallbackTerrainDataAccess()
        : terrain_callback_set_(false), environmental_callback_set_(false) {
    }

    CallbackTerrainDataAccess::CallbackTerrainDataAccess(CallbackTerrainDataAccess&& other) noexcept
        : terrain_height_callback_(std::move(other.terrain_height_callback_)),
          environmental_callback_(std::move(other.environmental_callback_)),
          terrain_callback_set_(other.terrain_callback_set_.load()),
          environmental_callback_set_(other.environmental_callback_set_.load()) {
        other.terrain_callback_set_ = false;
        other.environmental_callback_set_ = false;
    }

    CallbackTerrainDataAccess& CallbackTerrainDataAccess::operator=(CallbackTerrainDataAccess&& other) noexcept {
        if (this != &other) {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            terrain_height_callback_ = std::move(other.terrain_height_callback_);
            environmental_callback_ = std::move(other.environmental_callback_);
            terrain_callback_set_ = other.terrain_callback_set_.load();
            environmental_callback_set_ = other.environmental_callback_set_.load();
            
            other.terrain_callback_set_ = false;
            other.environmental_callback_set_ = false;
        }
        return *this;
    }

    void CallbackTerrainDataAccess::setTerrainHeightCallback(std::function<double(double, double)> callback) {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        terrain_height_callback_ = std::move(callback);
        terrain_callback_set_ = true;
    }

    void CallbackTerrainDataAccess::setEnvironmentalCallback(std::function<EnvironmentalConditions(double, double)> callback) {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        environmental_callback_ = std::move(callback);
        environmental_callback_set_ = true;
    }

    double CallbackTerrainDataAccess::getTerrainHeight(double latitude, double longitude) {
        if (!validateCoordinates(latitude, longitude)) {
            throw InvalidCoordinateException("Invalid coordinates: lat=" + std::to_string(latitude) + 
                                          ", lon=" + std::to_string(longitude));
        }
        
        std::lock_guard<std::mutex> lock(callback_mutex_);
        if (!terrain_callback_set_ || !terrain_height_callback_) {
            throw TerrainDataException("Terrain height callback not set");
        }
        
        try {
            return terrain_height_callback_(latitude, longitude);
        } catch (const std::exception& e) {
            throw TerrainDataException("Terrain height callback failed: " + std::string(e.what()));
        }
    }

    EnvironmentalConditions CallbackTerrainDataAccess::getEnvironmentalConditions(double latitude, double longitude) {
        if (!validateCoordinates(latitude, longitude)) {
            throw InvalidCoordinateException("Invalid coordinates: lat=" + std::to_string(latitude) + 
                                          ", lon=" + std::to_string(longitude));
        }
        
        std::lock_guard<std::mutex> lock(callback_mutex_);
        if (!environmental_callback_set_ || !environmental_callback_) {
            throw EnvironmentalDataException("Environmental callback not set");
        }
        
        try {
            return environmental_callback_(latitude, longitude);
        } catch (const std::exception& e) {
            throw EnvironmentalDataException("Environmental callback failed: " + std::string(e.what()));
        }
    }

    bool CallbackTerrainDataAccess::isDataSourceAvailable() const noexcept {
        return terrain_callback_set_.load() && environmental_callback_set_.load();
    }

    std::string CallbackTerrainDataAccess::getDataSourceName() const {
        return "CallbackTerrainDataAccess";
    }

    // Base class validateCoordinates implementation
    bool TerrainDataAccess::validateCoordinates(double latitude, double longitude) const noexcept {
        return latitude >= -90.0 && latitude <= 90.0 &&
               longitude >= -180.0 && longitude <= 180.0 &&
               std::isfinite(latitude) && std::isfinite(longitude);
    }

    // MockTerrainDataAccess implementation
    MockTerrainDataAccess::MockTerrainDataAccess()
        : mock_terrain_height_(0.0) {
        // Initialize with default environmental conditions
        mock_environmental_conditions_.temperature = 20.0;
        mock_environmental_conditions_.humidity = 50.0;
        mock_environmental_conditions_.precipitation_type = "none";
        mock_environmental_conditions_.precipitation_intensity = 0.0;
        mock_environmental_conditions_.atmospheric_pressure = 1013.25;
        mock_environmental_conditions_.wind_speed = 0.0;
        mock_environmental_conditions_.wind_direction = 0.0;
        mock_environmental_conditions_.visibility = 10000.0;
    }

    void MockTerrainDataAccess::setMockTerrainHeight(double height) noexcept {
        mock_terrain_height_ = height;
    }

    void MockTerrainDataAccess::setMockEnvironmentalConditions(const EnvironmentalConditions& conditions) {
        std::lock_guard<std::mutex> lock(mock_data_mutex_);
        mock_environmental_conditions_ = conditions;
    }

    double MockTerrainDataAccess::getTerrainHeight(double latitude, double longitude) {
        if (!validateCoordinates(latitude, longitude)) {
            throw InvalidCoordinateException("Invalid coordinates: lat=" + std::to_string(latitude) + 
                                          ", lon=" + std::to_string(longitude));
        }
        
        return mock_terrain_height_.load();
    }

    EnvironmentalConditions MockTerrainDataAccess::getEnvironmentalConditions(double latitude, double longitude) {
        if (!validateCoordinates(latitude, longitude)) {
            throw InvalidCoordinateException("Invalid coordinates: lat=" + std::to_string(latitude) + 
                                          ", lon=" + std::to_string(longitude));
        }
        
        std::lock_guard<std::mutex> lock(mock_data_mutex_);
        return mock_environmental_conditions_;
    }

    bool MockTerrainDataAccess::isDataSourceAvailable() const noexcept {
        return true; // Mock is always available
    }

    std::string MockTerrainDataAccess::getDataSourceName() const {
        return "MockTerrainDataAccess";
    }


    // TerrainDataAccessFactory implementation
    std::unique_ptr<TerrainDataAccess> TerrainDataAccessFactory::createCallbackAccess() {
        return std::make_unique<CallbackTerrainDataAccess>();
    }

    std::unique_ptr<TerrainDataAccess> TerrainDataAccessFactory::createMockAccess() {
        return std::make_unique<MockTerrainDataAccess>();
    }

    std::unique_ptr<TerrainDataAccess> TerrainDataAccessFactory::createFromConfig(const std::string& configType) {
        if (configType == "callback") {
            return createCallbackAccess();
        } else if (configType == "mock") {
            return createMockAccess();
        } else {
            throw ConfigurationException("Unknown configuration type: " + configType);
        }
    }

} // namespace FGCom_TerrainEnvironmental
