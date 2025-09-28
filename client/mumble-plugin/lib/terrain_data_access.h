#ifndef TERRAIN_DATA_ACCESS_H
#define TERRAIN_DATA_ACCESS_H

#include <string>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>

namespace FGCom_TerrainEnvironmental {

    // Forward declarations
    class Coordinate;
    struct TerrainAltitudeData;
    
    // Environmental conditions structure
    struct EnvironmentalConditions {
        double temperature;
        double humidity;
        std::string precipitation_type;
        double precipitation_intensity;
        double atmospheric_pressure;
        double wind_speed;
        double wind_direction;
        double visibility;
        
        EnvironmentalConditions() noexcept
            : temperature(20.0), humidity(50.0), precipitation_type("none"),
              precipitation_intensity(0.0), atmospheric_pressure(1013.25),
              wind_speed(0.0), wind_direction(0.0), visibility(10000.0) {}
    };

    /**
     * @brief Pure data access interface for terrain operations
     * 
     * Implements separation of concerns by isolating data access
     * from business logic and caching mechanisms.
     */
    class TerrainDataAccess {
    public:
        virtual ~TerrainDataAccess() = default;

        /**
         * @brief Get terrain height at specific coordinates
         * 
         * @param latitude Latitude in degrees
         * @param longitude Longitude in degrees
         * @return double Terrain height in meters above sea level
         * @throws TerrainDataException if data cannot be retrieved
         */
        virtual double getTerrainHeight(double latitude, double longitude) = 0;

        /**
         * @brief Get environmental conditions at coordinates
         * 
         * @param latitude Latitude in degrees
         * @param longitude Longitude in degrees
         * @return EnvironmentalConditions Environmental data
         * @throws EnvironmentalDataException if data cannot be retrieved
         */
        virtual EnvironmentalConditions getEnvironmentalConditions(double latitude, double longitude) = 0;

        /**
         * @brief Check if data source is available
         * 
         * @return bool True if data source is available
         */
        virtual bool isDataSourceAvailable() const noexcept = 0;

        /**
         * @brief Get data source name
         * 
         * @return std::string Data source name
         */
        virtual std::string getDataSourceName() const = 0;

    protected:
        /**
         * @brief Validate coordinate bounds
         * 
         * @param latitude Latitude to validate
         * @param longitude Longitude to validate
         * @return bool True if coordinates are valid
         */
        bool validateCoordinates(double latitude, double longitude) const noexcept;
    };

    /**
     * @brief Callback-based terrain data access
     * 
     * Uses external callbacks for terrain data retrieval.
     * Implements proper error handling and validation.
     */
    class CallbackTerrainDataAccess : public TerrainDataAccess {
    public:
        explicit CallbackTerrainDataAccess();
        ~CallbackTerrainDataAccess() override = default;

        // Non-copyable, movable
        CallbackTerrainDataAccess(const CallbackTerrainDataAccess&) = delete;
        CallbackTerrainDataAccess& operator=(const CallbackTerrainDataAccess&) = delete;
        CallbackTerrainDataAccess(CallbackTerrainDataAccess&&) noexcept;
        CallbackTerrainDataAccess& operator=(CallbackTerrainDataAccess&&) noexcept;

        /**
         * @brief Set terrain height callback
         * 
         * @param callback Function to get terrain height
         */
        void setTerrainHeightCallback(std::function<double(double, double)> callback);

        /**
         * @brief Set environmental conditions callback
         * 
         * @param callback Function to get environmental conditions
         */
        void setEnvironmentalCallback(std::function<EnvironmentalConditions(double, double)> callback);

        // TerrainDataAccess interface
        double getTerrainHeight(double latitude, double longitude) override;
        EnvironmentalConditions getEnvironmentalConditions(double latitude, double longitude) override;
        bool isDataSourceAvailable() const noexcept override;
        std::string getDataSourceName() const override;

    private:
        mutable std::mutex callback_mutex_;
        std::function<double(double, double)> terrain_height_callback_;
        std::function<EnvironmentalConditions(double, double)> environmental_callback_;
        std::atomic<bool> terrain_callback_set_;
        std::atomic<bool> environmental_callback_set_;
    };

    /**
     * @brief Mock terrain data access for testing
     * 
     * Provides predictable data for unit testing and development.
     */
    class MockTerrainDataAccess : public TerrainDataAccess {
    public:
        explicit MockTerrainDataAccess();
        ~MockTerrainDataAccess() override = default;

        // Non-copyable, non-movable
        MockTerrainDataAccess(const MockTerrainDataAccess&) = delete;
        MockTerrainDataAccess& operator=(const MockTerrainDataAccess&) = delete;
        MockTerrainDataAccess(MockTerrainDataAccess&&) = delete;
        MockTerrainDataAccess& operator=(MockTerrainDataAccess&&) = delete;

        /**
         * @brief Set mock terrain height
         * 
         * @param height Default terrain height to return
         */
        void setMockTerrainHeight(double height) noexcept;

        /**
         * @brief Set mock environmental conditions
         * 
         * @param conditions Environmental conditions to return
         */
        void setMockEnvironmentalConditions(const EnvironmentalConditions& conditions);

        // TerrainDataAccess interface
        double getTerrainHeight(double latitude, double longitude) override;
        EnvironmentalConditions getEnvironmentalConditions(double latitude, double longitude) override;
        bool isDataSourceAvailable() const noexcept override;
        std::string getDataSourceName() const override;

    private:
        std::atomic<double> mock_terrain_height_;
        EnvironmentalConditions mock_environmental_conditions_;
        mutable std::mutex mock_data_mutex_;
    };

    /**
     * @brief Factory for creating terrain data access instances
     * 
     * Implements factory pattern for creating different types of data access.
     */
    class TerrainDataAccessFactory {
    public:
        /**
         * @brief Create callback-based data access
         * 
         * @return std::unique_ptr<TerrainDataAccess> Data access instance
         */
        static std::unique_ptr<TerrainDataAccess> createCallbackAccess();

        /**
         * @brief Create mock data access for testing
         * 
         * @return std::unique_ptr<TerrainDataAccess> Mock data access instance
         */
        static std::unique_ptr<TerrainDataAccess> createMockAccess();

        /**
         * @brief Create data access based on configuration
         * 
         * @param configType Configuration type
         * @return std::unique_ptr<TerrainDataAccess> Data access instance
         */
        static std::unique_ptr<TerrainDataAccess> createFromConfig(const std::string& configType);
    };

} // namespace FGCom_TerrainEnvironmental

#endif // TERRAIN_DATA_ACCESS_H
