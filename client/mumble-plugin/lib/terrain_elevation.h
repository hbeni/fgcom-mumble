/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/Supermagnum/fgcom-mumble).
 * Copyright (c) 2024 FGCom-mumble Contributors
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef FGCOM_TERRAIN_ELEVATION_H
#define FGCOM_TERRAIN_ELEVATION_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <future>
#include <functional>
#include <queue>

// Forward declarations
struct TerrainProfile;
struct ObstructionResult;
struct FresnelZoneResult;

/**
 * @brief Terrain elevation data structure
 */
struct TerrainPoint {
    double latitude;
    double longitude;
    double elevation_m;
    double distance_km;
    
    TerrainPoint() : latitude(0.0), longitude(0.0), elevation_m(0.0), distance_km(0.0) {}
    TerrainPoint(double lat, double lon, double elev, double dist = 0.0) 
        : latitude(lat), longitude(lon), elevation_m(elev), distance_km(dist) {}
};

/**
 * @brief Terrain profile between two points
 */
struct TerrainProfile {
    std::vector<TerrainPoint> points;
    double max_elevation_m;
    double min_elevation_m;
    double average_elevation_m;
    bool line_of_sight_clear;
    double obstruction_height_m;
    double obstruction_distance_km;
    
    TerrainProfile() : max_elevation_m(0.0), min_elevation_m(0.0), average_elevation_m(0.0),
                      line_of_sight_clear(true), obstruction_height_m(0.0), obstruction_distance_km(0.0) {}
};

/**
 * @brief Terrain obstruction analysis result
 */
struct ObstructionResult {
    bool blocked;
    double obstruction_height_m;
    double obstruction_distance_km;
    double terrain_loss_db;
    double diffraction_loss_db;
    bool fresnel_zone_clear;
    double fresnel_clearance_percent;
    std::string obstruction_type;  // "mountain", "building", "hill", "none"
    
    ObstructionResult() : blocked(false), obstruction_height_m(0.0), obstruction_distance_km(0.0),
                         terrain_loss_db(0.0), diffraction_loss_db(0.0), fresnel_zone_clear(true),
                         fresnel_clearance_percent(0.0), obstruction_type("none") {}
};

/**
 * @brief Fresnel zone calculation result
 */
struct FresnelZoneResult {
    double fresnel_radius_m;
    double clearance_percent;
    bool zone_clear;
    double required_clearance_m;
    double actual_clearance_m;
    
    FresnelZoneResult() : fresnel_radius_m(0.0), clearance_percent(0.0), zone_clear(true),
                         required_clearance_m(0.0), actual_clearance_m(0.0) {}
};

/**
 * @brief ASTER GDEM tile information
 */
struct ASTERGDEMTile {
    std::string filename;
    double min_lat, max_lat;
    double min_lon, max_lon;
    std::string file_path;
    bool loaded;
    size_t file_size_bytes;
    
    ASTERGDEMTile() : min_lat(0.0), max_lat(0.0), min_lon(0.0), max_lon(0.0), 
                     loaded(false), file_size_bytes(0) {}
};

/**
 * @brief Configuration for terrain elevation system
 */
struct TerrainElevationConfig {
    bool enabled;
    std::string elevation_source;
    std::string data_path;
    bool auto_download;
    std::string download_url;
    size_t cache_size_mb;
    bool enable_obstruction_detection;
    double terrain_resolution_m;
    bool enable_fresnel_zone;
    double fresnel_clearance_percent;
    bool enable_diffraction;
    double max_profile_distance_km;
    bool enable_profile_caching;
    size_t profile_cache_size_mb;
    
    TerrainElevationConfig() : enabled(false), elevation_source("aster_gdem"),
                              data_path("/usr/share/fgcom-mumble/aster_gdem"), auto_download(false),
                              download_url("https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/"),
                              cache_size_mb(1000), enable_obstruction_detection(true),
                              terrain_resolution_m(30.0), enable_fresnel_zone(true),
                              fresnel_clearance_percent(0.6), enable_diffraction(true),
                              max_profile_distance_km(100.0), enable_profile_caching(true),
                              profile_cache_size_mb(500) {}
};

/**
 * @brief Main terrain elevation manager class
 */
class FGCom_TerrainElevationManager {
private:
    TerrainElevationConfig config;
    std::map<std::string, ASTERGDEMTile> tile_cache;
    std::map<std::string, TerrainProfile> profile_cache;
    std::mutex cache_mutex;
    std::mutex tile_mutex;
    std::atomic<bool> initialized;
    std::atomic<bool> shutdown_requested;
    
    // Thread pool for async operations
    std::vector<std::thread> worker_threads;
    std::queue<std::function<void()>> task_queue;
    std::mutex task_mutex;
    std::condition_variable task_cv;
    std::atomic<bool> workers_running;
    
    // Statistics
    std::atomic<size_t> tiles_loaded;
    std::atomic<size_t> profiles_calculated;
    std::atomic<size_t> cache_hits;
    std::atomic<size_t> cache_misses;
    
public:
    FGCom_TerrainElevationManager();
    ~FGCom_TerrainElevationManager();
    
    // Initialization and configuration
    bool initialize(const TerrainElevationConfig& config);
    void shutdown();
    bool isInitialized() const { return initialized.load(); }
    
    // Configuration
    void setConfig(const TerrainElevationConfig& config);
    TerrainElevationConfig getConfig() const { return config; }
    
    // Core elevation functions
    double getElevation(double latitude, double longitude);
    TerrainProfile getTerrainProfile(double lat1, double lon1, double lat2, double lon2, 
                                   double resolution_m = 30.0);
    ObstructionResult analyzeObstruction(double lat1, double lon1, double alt1,
                                        double lat2, double lon2, double alt2,
                                        double frequency_mhz);
    
    // ASTER GDEM specific functions
    bool loadASTERGDEMTile(double latitude, double longitude);
    std::vector<ASTERGDEMTile> getAvailableTiles() const;
    bool downloadASTERGDEMTile(const std::string& tile_name);
    
    // Fresnel zone calculations
    FresnelZoneResult calculateFresnelZone(double lat1, double lon1, double alt1,
                                         double lat2, double lon2, double alt2,
                                         double frequency_mhz);
    
    // Diffraction calculations
    double calculateDiffractionLoss(double obstruction_height_m, double distance_km,
                                  double frequency_mhz);
    
    // Cache management
    void clearCache();
    void clearProfileCache();
    size_t getCacheSize() const;
    size_t getProfileCacheSize() const;
    
    // Statistics
    struct Statistics {
        size_t tiles_loaded;
        size_t profiles_calculated;
        size_t cache_hits;
        size_t cache_misses;
        double cache_hit_rate;
        size_t memory_usage_mb;
    };
    Statistics getStatistics() const;
    
    // Error handling
    std::string getLastError() const;
    void setLastError(const std::string& error) const;
    
private:
    // Internal helper functions
    std::string getTileName(double latitude, double longitude) const;
    bool loadTileFromFile(const std::string& tile_path, ASTERGDEMTile& tile);
    double interpolateElevation(const ASTERGDEMTile& tile, double lat, double lon);
    std::vector<TerrainPoint> generateProfilePoints(double lat1, double lon1, 
                                                   double lat2, double lon2, 
                                                   double resolution_m);
    bool isPointInTile(const ASTERGDEMTile& tile, double lat, double lon) const;
    
    // Worker thread functions
    void workerThread();
    void submitTask(std::function<void()> task);
    
    // Cache management
    void evictOldCacheEntries();
    bool isCacheFull() const;
    
    // Error handling
    mutable std::string last_error;
    void logError(const std::string& error) const;
};

/**
 * @brief ASTER GDEM tile loader class
 */
class FGCom_ASTERGDEMLoader {
private:
    std::string data_path;
    std::string download_url;
    std::atomic<bool> download_enabled;
    
public:
    FGCom_ASTERGDEMLoader(const std::string& data_path, const std::string& download_url);
    ~FGCom_ASTERGDEMLoader();
    
    // Tile management
    bool loadTile(double latitude, double longitude, ASTERGDEMTile& tile);
    bool downloadTile(const std::string& tile_name);
    std::vector<std::string> getAvailableTiles() const;
    bool isTileAvailable(double latitude, double longitude) const;
    
    // File operations
    std::string getTilePath(double latitude, double longitude) const;
    std::string getTileFilename(double latitude, double longitude) const;
    bool createDataDirectory();
    
    // Download operations
    void setDownloadEnabled(bool enabled) { download_enabled.store(enabled); }
    bool isDownloadEnabled() const { return download_enabled.load(); }
    
    // Error handling
    std::string getLastError() const;
    void setLastError(const std::string& error);
    
private:
    mutable std::string last_error;
    std::string constructDownloadURL(const std::string& tile_name) const;
    bool downloadFile(const std::string& url, const std::string& filepath);
    void logError(const std::string& error) const;
};

/**
 * @brief Terrain obstruction analyzer
 */
class FGCom_TerrainObstructionAnalyzer {
private:
    double fresnel_clearance_percent;
    bool enable_diffraction;
    bool enable_fresnel_zone;
    
public:
    FGCom_TerrainObstructionAnalyzer(double fresnel_clearance = 0.6, 
                                    bool enable_diffraction = true,
                                    bool enable_fresnel = true);
    
    // Obstruction analysis
    ObstructionResult analyzeObstruction(const TerrainProfile& profile,
                                       double alt1, double alt2,
                                       double frequency_mhz);
    
    // Fresnel zone calculations
    FresnelZoneResult calculateFresnelZone(const TerrainProfile& profile,
                                         double alt1, double alt2,
                                         double frequency_mhz);
    
    // Diffraction calculations
    double calculateDiffractionLoss(double obstruction_height_m, double distance_km,
                                  double frequency_mhz);
    
    // Line of sight calculations
    bool isLineOfSightClear(const TerrainProfile& profile, double alt1, double alt2);
    
    // Configuration
    void setFresnelClearancePercent(double percent) { fresnel_clearance_percent = percent; }
    void setDiffractionEnabled(bool enabled) { enable_diffraction = enabled; }
    void setFresnelZoneEnabled(bool enabled) { enable_fresnel_zone = enabled; }
    
private:
    double calculateFresnelRadius(double distance_km, double frequency_mhz) const;
    double calculateRequiredClearance(const TerrainProfile& profile, double alt1, double alt2) const;
    bool checkFresnelZoneClearance(const TerrainProfile& profile, double alt1, double alt2,
                                 double frequency_mhz) const;
};

#endif // FGCOM_TERRAIN_ELEVATION_H
