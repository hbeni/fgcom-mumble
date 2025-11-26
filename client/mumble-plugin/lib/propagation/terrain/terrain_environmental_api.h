#ifndef TERRAIN_ENVIRONMENTAL_API_H
#define TERRAIN_ENVIRONMENTAL_API_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include "terrain_exceptions.h"
#include "terrain_state_machine.h"
#include "terrain_data_access.h"
#include "terrain_cache.h"
#include "terrain_statistics.h"

namespace FGCom_TerrainEnvironmental {

    /**
     * @brief Represents a 3D coordinate with comprehensive validation
     * 
     * This class ensures all coordinates are within valid bounds and provides
     * thread-safe access to coordinate data with proper error handling.
     */
    class Coordinate {
    public:
        /**
         * @brief Construct coordinate with validation
         * 
         * @param latitude Latitude in degrees (-90 to 90)
         * @param longitude Longitude in degrees (-180 to 180)
         * @param altitude Altitude in meters (-500 to 10000)
         * @throws InvalidCoordinateException if coordinates are invalid
         */
        Coordinate(double latitude, double longitude, double altitude);
        
        // Getters with const correctness
        double getLatitude() const noexcept;
        double getLongitude() const noexcept;
        double getAltitude() const noexcept;
        
        // Validation
        bool isValid() const noexcept;
        
        // Distance calculation with error handling
        double calculateDistance(const Coordinate& other) const;
        
        // String representation
        std::string toString() const;
        
    private:
        const double latitude_;
        const double longitude_;
        const double altitude_;
        
        // Validation bounds - constexpr for compile-time evaluation
        static constexpr double MIN_LATITUDE = -90.0;
        static constexpr double MAX_LATITUDE = 90.0;
        static constexpr double MIN_LONGITUDE = -180.0;
        static constexpr double MAX_LONGITUDE = 180.0;
        static constexpr double MIN_ALTITUDE = -500.0;
        static constexpr double MAX_ALTITUDE = 10000.0;
        
        // Validation helper
        void validateCoordinates(double lat, double lon, double alt) const;
    };

    /**
     * @brief Line of sight data structure with comprehensive validation
     * 
     * This structure contains all line-of-sight information with proper
     * bounds checking and thread safety.
     */
    struct LineOfSightData {
        bool line_of_sight_blocked;
        double obstruction_distance;
        double obstruction_height;
        double clearance_angle;
        std::vector<std::pair<double, double>> terrain_profile;
        
        // Validation
        bool isValid() const noexcept;
        
        // Default constructor with safe defaults
        LineOfSightData() noexcept;
    };

    /**
     * @brief Terrain altitude data with validation
     */
    struct TerrainAltitudeData {
        double ground_altitude;
        std::string terrain_type;
        std::string surface_material;
        
        bool isValid() const noexcept;
        TerrainAltitudeData() noexcept;
    };

    // EnvironmentalConditions is defined in terrain_data_access.h

    /**
     * @brief Noise floor data with frequency-dependent calculations
     */
    struct NoiseFloorData {
        double ambient_noise_level;
        double atmospheric_noise;
        double man_made_noise;
        double total_noise_floor;
        std::string environment_type;
        
        struct NoiseBreakdown {
            double thermal;
            double galactic;
            double atmospheric;
            double man_made;
        } noise_breakdown;
        
        bool isValid() const noexcept;
        NoiseFloorData() noexcept;
    };

    /**
     * @brief Main terrain data provider with proper separation of concerns
     * 
     * This class orchestrates terrain operations using dependency injection
     * and proper separation of concerns. It delegates to specialized components
     * for data access, caching, and statistics.
     */
    class TerrainDataProvider {
    public:
        /**
         * @brief Construct terrain data provider with dependency injection
         * 
         * @param dataAccess Data access implementation
         * @param cache Cache implementation (optional)
         * @param statistics Statistics implementation (optional)
         */
        explicit TerrainDataProvider(std::unique_ptr<TerrainDataAccess> dataAccess,
                                   std::unique_ptr<TerrainCache> cache = nullptr,
                                   std::unique_ptr<TerrainStatistics> statistics = nullptr);
        
        ~TerrainDataProvider();
        
        // Non-copyable, movable
        TerrainDataProvider(const TerrainDataProvider&) = delete;
        TerrainDataProvider& operator=(const TerrainDataProvider&) = delete;
        TerrainDataProvider(TerrainDataProvider&&) noexcept;
        TerrainDataProvider& operator=(TerrainDataProvider&&) noexcept;
        
        /**
         * @brief Check line of sight between two coordinates
         * 
         * @param transmitter Transmitter coordinate
         * @param receiver Receiver coordinate
         * @return LineOfSightData Line of sight information
         * @throws InvalidCoordinateException if coordinates are invalid
         * @throws TerrainDataException if terrain data cannot be accessed
         * @throws CalculationException if LOS calculation fails
         */
        LineOfSightData checkLineOfSight(const Coordinate& transmitter, 
                                       const Coordinate& receiver);
        
        /**
         * @brief Get terrain altitude at specific location
         * 
         * @param coordinate Location coordinate
         * @return TerrainAltitudeData Terrain altitude information
         * @throws std::invalid_argument if coordinate is invalid
         * @throws std::runtime_error if terrain data unavailable
         */
        TerrainAltitudeData getTerrainAltitude(const Coordinate& coordinate);
        
        /**
         * @brief Get environmental conditions at location
         * 
         * @param coordinate Location coordinate
         * @return EnvironmentalConditions Environmental data
         * @throws std::invalid_argument if coordinate is invalid
         * @throws std::runtime_error if environmental data unavailable
         */
        EnvironmentalConditions getEnvironmentalConditions(const Coordinate& coordinate);
        
        /**
         * @brief Calculate noise floor for location and frequency
         * 
         * @param coordinate Location coordinate
         * @param frequency Radio frequency in MHz
         * @param timeOfDay Time of day ("day" or "night")
         * @param season Season ("spring", "summer", "autumn", "winter")
         * @return NoiseFloorData Noise floor information
         * @throws std::invalid_argument if parameters are invalid
         * @throws std::runtime_error if calculation fails
         */
        NoiseFloorData calculateNoiseFloor(const Coordinate& coordinate,
                                          double frequency,
                                          const std::string& timeOfDay,
                                          const std::string& season);
        
        /**
         * @brief Set terrain data callback for external terrain systems
         * 
         * @param callback Function to get terrain height at coordinates
         */
        void setTerrainHeightCallback(std::function<double(double, double)> callback);
        
        /**
         * @brief Set environmental data callback for external weather systems
         * 
         * @param callback Function to get environmental data at coordinates
         */
        void setEnvironmentalCallback(std::function<EnvironmentalConditions(double, double)> callback);
        
        /**
         * @brief Enable/disable caching for performance optimization
         * 
         * @param enable True to enable caching, false to disable
         */
        void setCachingEnabled(bool enable) noexcept;
        
        /**
         * @brief Clear all cached data
         */
        void clearCache() noexcept;
        
        /**
         * @brief Get performance statistics
         * 
         * @return std::string Performance statistics as JSON
         */
        std::string getPerformanceStats() const;
        
    private:
        // Dependency injection - proper separation of concerns
        std::unique_ptr<TerrainDataAccess> data_access_;
        std::unique_ptr<TerrainCache> cache_;
        std::unique_ptr<TerrainStatistics> statistics_;
        std::unique_ptr<TerrainStateMachine> state_machine_;
        
        // Thread safety
        mutable std::mutex operation_mutex_;
        
        // Internal validation methods
        bool validateCoordinate(const Coordinate& coord) const noexcept;
        bool validateFrequency(double frequency) const noexcept;
        bool validateTimeOfDay(const std::string& timeOfDay) const noexcept;
        bool validateSeason(const std::string& season) const noexcept;
        
        // Internal calculation methods with proper error handling
        double calculateTerrainHeight(double latitude, double longitude) const;
        EnvironmentalConditions getEnvironmentalData(double latitude, double longitude) const;
        double calculateAtmosphericNoise(double frequency, const EnvironmentalConditions& env) const;
        double calculateManMadeNoise(const std::string& environmentType) const;
        
        // Cache management with proper error handling
        std::string generateCacheKey(const std::string& operation, 
                                   const Coordinate& coord1, 
                                   const Coordinate& coord2 = Coordinate(0, 0, 0)) const;
        bool isCacheValid(const std::string& key) const;
        void updateCache(const std::string& key, const std::string& data);
        std::string getCachedData(const std::string& key);
    };

    /**
     * @brief API server for terrain and environmental data with proper security
     * 
     * This class provides HTTP API endpoints for terrain and environmental data
     * with comprehensive error handling, input validation, and security measures.
     */
    class TerrainEnvironmentalAPIServer {
    public:
        /**
         * @brief Construct API server with dependency injection
         * 
         * @param provider Terrain data provider
         * @throws ConfigurationException if provider is null
         */
        explicit TerrainEnvironmentalAPIServer(std::shared_ptr<TerrainDataProvider> provider);
        ~TerrainEnvironmentalAPIServer();
        
        // Non-copyable, movable
        TerrainEnvironmentalAPIServer(const TerrainEnvironmentalAPIServer&) = delete;
        TerrainEnvironmentalAPIServer& operator=(const TerrainEnvironmentalAPIServer&) = delete;
        TerrainEnvironmentalAPIServer(TerrainEnvironmentalAPIServer&&) noexcept;
        TerrainEnvironmentalAPIServer& operator=(TerrainEnvironmentalAPIServer&&) noexcept;
        
        /**
         * @brief Start the API server with proper error handling
         * 
         * @param port Port number to listen on (1-65535)
         * @param host Host address to bind to
         * @throws APIServerException if server fails to start
         * @throws ConfigurationException if port is invalid
         */
        void start(int port = 8080, const std::string& host = "localhost");
        
        /**
         * @brief Stop the API server
         */
        void stop() noexcept;
        
        /**
         * @brief Check if server is running
         * 
         * @return bool True if server is running
         */
        bool isRunning() const noexcept;
        
    private:
        std::shared_ptr<TerrainDataProvider> provider_;
        std::atomic<bool> running_;
        mutable std::mutex server_mutex_;
        
        // Security and validation
        static constexpr size_t MAX_REQUEST_SIZE = 1024 * 1024; // 1MB max request
        static constexpr size_t MAX_COORDINATE_PRECISION = 6;   // 6 decimal places max
        
        // HTTP request handlers with proper error handling
        std::string handleLOSCheck(const std::string& requestBody);
        std::string handleAltitudeQuery(const std::string& requestBody);
        std::string handleEnvironmentalQuery(const std::string& requestBody);
        std::string handleNoiseFloorQuery(const std::string& requestBody);
        
        // Input validation and sanitization
        bool validateRequestSize(const std::string& request) const noexcept;
        bool sanitizeInput(std::string& input) const;
        bool validateCoordinateInput(double lat, double lon, double alt) const noexcept;
        
        // JSON parsing and validation with security
        bool parseCoordinate(const std::string& json, Coordinate& coord);
        bool parseRequest(const std::string& json, std::string& error);
        
        // Response generation with proper formatting
        std::string generateErrorResponse(const std::string& error, int code);
        std::string generateSuccessResponse(const std::string& data);
        
        // Security measures
        bool isRequestRateLimited(const std::string& clientIP) const;
        void logSecurityEvent(const std::string& event, const std::string& details) const;
    };

} // namespace FGCom_TerrainEnvironmental

#endif // TERRAIN_ENVIRONMENTAL_API_H
