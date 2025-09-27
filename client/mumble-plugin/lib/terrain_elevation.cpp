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

#include "terrain_elevation.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <filesystem>
#include <chrono>
#include <queue>
#include <condition_variable>
#include <thread>
#include <future>
// #include <curl/curl.h>  // CURL not available, using alternative implementation

// Helper function for CURL downloads
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    std::ofstream* file = static_cast<std::ofstream*>(userp);
    file->write(static_cast<char*>(contents), total_size);
    return total_size;
}

// =============================================================================
// FGCom_TerrainElevationManager Implementation
// =============================================================================

FGCom_TerrainElevationManager::FGCom_TerrainElevationManager() 
    : initialized(false), shutdown_requested(false), workers_running(false),
      tiles_loaded(0), profiles_calculated(0), cache_hits(0), cache_misses(0) {
}

FGCom_TerrainElevationManager::~FGCom_TerrainElevationManager() {
    shutdown();
}

bool FGCom_TerrainElevationManager::initialize(const TerrainElevationConfig& config) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    
    if (initialized.load()) {
        return true;
    }
    
    this->config = config;
    
    if (!config.enabled) {
        initialized.store(true);
        return true;
    }
    
    // Create data directory if it doesn't exist
    if (!std::filesystem::exists(config.data_path)) {
        try {
            std::filesystem::create_directories(config.data_path);
        } catch (const std::exception& e) {
            setLastError("Failed to create data directory: " + std::string(e.what()));
            return false;
        }
    }
    
    // Start worker threads
    workers_running.store(true);
    for (size_t i = 0; i < std::thread::hardware_concurrency(); ++i) {
        worker_threads.emplace_back(&FGCom_TerrainElevationManager::workerThread, this);
    }
    
    initialized.store(true);
    return true;
}

void FGCom_TerrainElevationManager::shutdown() {
    if (!initialized.load()) {
        return;
    }
    
    shutdown_requested.store(true);
    workers_running.store(false);
    
    // Notify all worker threads
    {
        std::lock_guard<std::mutex> lock(task_mutex);
        task_cv.notify_all();
    }
    
    // Wait for worker threads to finish
    for (auto& thread : worker_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads.clear();
    
    // Clear caches
    clearCache();
    clearProfileCache();
    
    initialized.store(false);
}

void FGCom_TerrainElevationManager::setConfig(const TerrainElevationConfig& config) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    this->config = config;
}

double FGCom_TerrainElevationManager::getElevation(double latitude, double longitude) {
    if (!config.enabled || !initialized.load()) {
        return 0.0;
    }
    
    std::string tile_name = getTileName(latitude, longitude);
    
    // Check cache first
    {
        std::lock_guard<std::mutex> lock(tile_mutex);
        auto it = tile_cache.find(tile_name);
        if (it != tile_cache.end() && it->second.loaded) {
            cache_hits++;
            return interpolateElevation(it->second, latitude, longitude);
        }
    }
    
    cache_misses++;
    
    // Load tile if not in cache
    if (loadASTERGDEMTile(latitude, longitude)) {
        std::lock_guard<std::mutex> lock(tile_mutex);
        auto it = tile_cache.find(tile_name);
        if (it != tile_cache.end() && it->second.loaded) {
            return interpolateElevation(it->second, latitude, longitude);
        }
    }
    
    return 0.0; // Default elevation if tile not available
}

TerrainProfile FGCom_TerrainElevationManager::getTerrainProfile(double lat1, double lon1, 
                                                               double lat2, double lon2, 
                                                               double resolution_m) {
    TerrainProfile profile;
    
    if (!config.enabled || !initialized.load()) {
        return profile;
    }
    
    // Check profile cache
    std::string cache_key = std::to_string(lat1) + "," + std::to_string(lon1) + "," +
                           std::to_string(lat2) + "," + std::to_string(lon2) + "," +
                           std::to_string(resolution_m);
    
    if (config.enable_profile_caching) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto it = profile_cache.find(cache_key);
        if (it != profile_cache.end()) {
            cache_hits++;
            return it->second;
        }
    }
    
    cache_misses++;
    
    // Generate terrain profile
    profile.points = generateProfilePoints(lat1, lon1, lat2, lon2, resolution_m);
    
    if (profile.points.empty()) {
        return profile;
    }
    
    // Calculate statistics
    double sum_elevation = 0.0;
    profile.max_elevation_m = profile.points[0].elevation_m;
    profile.min_elevation_m = profile.points[0].elevation_m;
    
    for (const auto& point : profile.points) {
        sum_elevation += point.elevation_m;
        profile.max_elevation_m = std::max(profile.max_elevation_m, point.elevation_m);
        profile.min_elevation_m = std::min(profile.min_elevation_m, point.elevation_m);
    }
    
    profile.average_elevation_m = sum_elevation / profile.points.size();
    
    // Check line of sight
    profile.line_of_sight_clear = true;
    profile.obstruction_height_m = 0.0;
    profile.obstruction_distance_km = 0.0;
    
    // Simple line of sight check (can be enhanced with proper geometric calculations)
    for (size_t i = 0; i < profile.points.size(); ++i) {
        const auto& point = profile.points[i];
        double expected_elevation = profile.points[0].elevation_m + 
            (profile.points.back().elevation_m - profile.points[0].elevation_m) * 
            (point.distance_km / profile.points.back().distance_km);
        
        if (point.elevation_m > expected_elevation + 10.0) { // 10m threshold
            profile.line_of_sight_clear = false;
            if (point.elevation_m > profile.obstruction_height_m) {
                profile.obstruction_height_m = point.elevation_m;
                profile.obstruction_distance_km = point.distance_km;
            }
        }
    }
    
    // Cache the profile
    if (config.enable_profile_caching) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        profile_cache[cache_key] = profile;
        profiles_calculated++;
    }
    
    return profile;
}

ObstructionResult FGCom_TerrainElevationManager::analyzeObstruction(double lat1, double lon1, double alt1,
                                                                   double lat2, double lon2, double alt2,
                                                                   double frequency_mhz) {
    ObstructionResult result;
    
    if (!config.enabled || !initialized.load()) {
        return result;
    }
    
    // Get terrain profile
    TerrainProfile profile = getTerrainProfile(lat1, lon1, lat2, lon2, config.terrain_resolution_m);
    
    if (profile.points.empty()) {
        return result;
    }
    
    // Create obstruction analyzer
    FGCom_TerrainObstructionAnalyzer analyzer(config.fresnel_clearance_percent,
                                              config.enable_diffraction,
                                              config.enable_fresnel_zone);
    
    // Analyze obstruction
    result = analyzer.analyzeObstruction(profile, alt1, alt2, frequency_mhz);
    
    return result;
}

bool FGCom_TerrainElevationManager::loadASTERGDEMTile(double latitude, double longitude) {
    std::string tile_name = getTileName(latitude, longitude);
    
    // Check if already loaded
    {
        std::lock_guard<std::mutex> lock(tile_mutex);
        auto it = tile_cache.find(tile_name);
        if (it != tile_cache.end() && it->second.loaded) {
            return true;
        }
    }
    
    // Create tile entry
    ASTERGDEMTile tile;
    tile.filename = tile_name + ".tif";
    tile.min_lat = std::floor(latitude);
    tile.max_lat = tile.min_lat + 1.0;
    tile.min_lon = std::floor(longitude);
    tile.max_lon = tile.min_lon + 1.0;
    tile.file_path = config.data_path + "/" + tile.filename;
    tile.loaded = false;
    
    // Try to load from file
    if (loadTileFromFile(tile.file_path, tile)) {
        std::lock_guard<std::mutex> lock(tile_mutex);
        tile_cache[tile_name] = tile;
        tiles_loaded++;
        return true;
    }
    
    // Try to download if auto-download is enabled
    if (config.auto_download) {
        FGCom_ASTERGDEMLoader loader(config.data_path, config.download_url);
        if (loader.downloadTile(tile_name)) {
            if (loadTileFromFile(tile.file_path, tile)) {
                std::lock_guard<std::mutex> lock(tile_mutex);
                tile_cache[tile_name] = tile;
                tiles_loaded++;
                return true;
            }
        }
    }
    
    return false;
}

std::vector<ASTERGDEMTile> FGCom_TerrainElevationManager::getAvailableTiles() const {
    std::vector<ASTERGDEMTile> tiles;
    
    const_cast<FGCom_TerrainElevationManager*>(this)->tile_mutex.lock();
    for (const auto& pair : tile_cache) {
        tiles.push_back(pair.second);
    }
    const_cast<FGCom_TerrainElevationManager*>(this)->tile_mutex.unlock();
    
    return tiles;
}

bool FGCom_TerrainElevationManager::downloadASTERGDEMTile(const std::string& tile_name) {
    FGCom_ASTERGDEMLoader loader(config.data_path, config.download_url);
    return loader.downloadTile(tile_name);
}

FresnelZoneResult FGCom_TerrainElevationManager::calculateFresnelZone(double lat1, double lon1, double alt1,
                                                                      double lat2, double lon2, double alt2,
                                                                      double frequency_mhz) {
    FresnelZoneResult result;
    
    if (!config.enabled || !initialized.load()) {
        return result;
    }
    
    // Get terrain profile
    TerrainProfile profile = getTerrainProfile(lat1, lon1, lat2, lon2, config.terrain_resolution_m);
    
    if (profile.points.empty()) {
        return result;
    }
    
    // Create obstruction analyzer
    FGCom_TerrainObstructionAnalyzer analyzer(config.fresnel_clearance_percent,
                                              config.enable_diffraction,
                                              config.enable_fresnel_zone);
    
    // Calculate Fresnel zone
    result = analyzer.calculateFresnelZone(profile, alt1, alt2, frequency_mhz);
    
    return result;
}

double FGCom_TerrainElevationManager::calculateDiffractionLoss(double obstruction_height_m, 
                                                              double distance_km,
                                                              double frequency_mhz) {
    if (!config.enable_diffraction) {
        return 0.0;
    }
    
    // Create obstruction analyzer
    FGCom_TerrainObstructionAnalyzer analyzer(config.fresnel_clearance_percent,
                                              config.enable_diffraction,
                                              config.enable_fresnel_zone);
    
    return analyzer.calculateDiffractionLoss(obstruction_height_m, distance_km, frequency_mhz);
}

void FGCom_TerrainElevationManager::clearCache() {
    std::lock_guard<std::mutex> lock(tile_mutex);
    tile_cache.clear();
    tiles_loaded.store(0);
}

void FGCom_TerrainElevationManager::clearProfileCache() {
    std::lock_guard<std::mutex> lock(cache_mutex);
    profile_cache.clear();
    profiles_calculated.store(0);
}

size_t FGCom_TerrainElevationManager::getCacheSize() const {
    const_cast<FGCom_TerrainElevationManager*>(this)->tile_mutex.lock();
    size_t size = tile_cache.size();
    const_cast<FGCom_TerrainElevationManager*>(this)->tile_mutex.unlock();
    return size;
}

size_t FGCom_TerrainElevationManager::getProfileCacheSize() const {
    const_cast<FGCom_TerrainElevationManager*>(this)->cache_mutex.lock();
    size_t size = profile_cache.size();
    const_cast<FGCom_TerrainElevationManager*>(this)->cache_mutex.unlock();
    return size;
}

FGCom_TerrainElevationManager::Statistics FGCom_TerrainElevationManager::getStatistics() const {
    Statistics stats;
    stats.tiles_loaded = tiles_loaded.load();
    stats.profiles_calculated = profiles_calculated.load();
    stats.cache_hits = cache_hits.load();
    stats.cache_misses = cache_misses.load();
    
    size_t total_requests = stats.cache_hits + stats.cache_misses;
    stats.cache_hit_rate = total_requests > 0 ? (double)stats.cache_hits / total_requests : 0.0;
    
    // Estimate memory usage
    stats.memory_usage_mb = (getCacheSize() * sizeof(ASTERGDEMTile) + 
                           getProfileCacheSize() * sizeof(TerrainProfile)) / (1024 * 1024);
    
    return stats;
}

std::string FGCom_TerrainElevationManager::getLastError() const {
    const_cast<FGCom_TerrainElevationManager*>(this)->cache_mutex.lock();
    std::string error = last_error;
    const_cast<FGCom_TerrainElevationManager*>(this)->cache_mutex.unlock();
    return error;
}

void FGCom_TerrainElevationManager::setLastError(const std::string& error) const {
    const_cast<FGCom_TerrainElevationManager*>(this)->cache_mutex.lock();
    const_cast<FGCom_TerrainElevationManager*>(this)->last_error = error;
    const_cast<FGCom_TerrainElevationManager*>(this)->cache_mutex.unlock();
}

// Private helper functions
std::string FGCom_TerrainElevationManager::getTileName(double latitude, double longitude) const {
    int lat_tile = static_cast<int>(std::floor(latitude));
    int lon_tile = static_cast<int>(std::floor(longitude));
    
    std::string lat_str = (lat_tile >= 0) ? "N" + std::to_string(lat_tile) : "S" + std::to_string(-lat_tile);
    std::string lon_str = (lon_tile >= 0) ? "E" + std::to_string(lon_tile) : "W" + std::to_string(-lon_tile);
    
    return lat_str + lon_str;
}

bool FGCom_TerrainElevationManager::loadTileFromFile(const std::string& tile_path, ASTERGDEMTile& tile) {
    if (!std::filesystem::exists(tile_path)) {
        return false;
    }
    
    try {
        // For now, we'll assume the tile is loaded successfully
        // In a real implementation, you would use a GeoTIFF library like GDAL
        tile.loaded = true;
        tile.file_size_bytes = std::filesystem::file_size(tile_path);
        return true;
    } catch (const std::exception& e) {
        setLastError("Failed to load tile from file: " + std::string(e.what()));
        return false;
    }
}

double FGCom_TerrainElevationManager::interpolateElevation(const ASTERGDEMTile& tile, double lat, double lon) {
    // Simplified elevation interpolation
    // In a real implementation, you would use proper GeoTIFF reading and interpolation
    if (!tile.loaded) {
        return 0.0;
    }
    
    // Simple bilinear interpolation approximation
    double lat_frac = lat - tile.min_lat;
    double lon_frac = lon - tile.min_lon;
    
    // This is a placeholder - real implementation would read actual elevation data
    return 100.0 + 50.0 * std::sin(lat_frac * M_PI) * std::cos(lon_frac * M_PI);
}

std::vector<TerrainPoint> FGCom_TerrainElevationManager::generateProfilePoints(double lat1, double lon1, 
                                                                             double lat2, double lon2, 
                                                                             double resolution_m) {
    std::vector<TerrainPoint> points;
    
    // Calculate distance and bearing
    double distance_km = 0.0;
    // double bearing_deg = 0.0;  // Not used in current implementation
    
    // Simple distance calculation (Haversine formula would be more accurate)
    double dlat = (lat2 - lat1) * M_PI / 180.0;
    double dlon = (lon2 - lon1) * M_PI / 180.0;
    double a = std::sin(dlat/2) * std::sin(dlat/2) + 
               std::cos(lat1 * M_PI / 180.0) * std::cos(lat2 * M_PI / 180.0) * 
               std::sin(dlon/2) * std::sin(dlon/2);
    double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1-a));
    distance_km = 6371.0 * c; // Earth radius in km
    
    // Calculate number of points based on resolution
    int num_points = static_cast<int>(distance_km * 1000.0 / resolution_m) + 1;
    
    for (int i = 0; i < num_points; ++i) {
        double fraction = static_cast<double>(i) / (num_points - 1);
        double lat = lat1 + (lat2 - lat1) * fraction;
        double lon = lon1 + (lon2 - lon1) * fraction;
        double dist = distance_km * fraction;
        
        double elevation = getElevation(lat, lon);
        
        points.emplace_back(lat, lon, elevation, dist);
    }
    
    return points;
}

bool FGCom_TerrainElevationManager::isPointInTile(const ASTERGDEMTile& tile, double lat, double lon) const {
    return lat >= tile.min_lat && lat < tile.max_lat && 
           lon >= tile.min_lon && lon < tile.max_lon;
}

void FGCom_TerrainElevationManager::workerThread() {
    while (workers_running.load()) {
        std::function<void()> task;
        
        {
            std::unique_lock<std::mutex> lock(task_mutex);
            task_cv.wait(lock, [this] { return !task_queue.empty() || !workers_running.load(); });
            
            if (!workers_running.load()) {
                break;
            }
            
            if (!task_queue.empty()) {
                task = task_queue.front();
                task_queue.pop();
            }
        }
        
        if (task) {
            try {
                task();
            } catch (const std::exception& e) {
                logError("Worker thread error: " + std::string(e.what()));
            }
        }
    }
}

void FGCom_TerrainElevationManager::submitTask(std::function<void()> task) {
    if (workers_running.load()) {
        std::lock_guard<std::mutex> lock(task_mutex);
        task_queue.push(task);
        task_cv.notify_one();
    }
}

void FGCom_TerrainElevationManager::evictOldCacheEntries() {
    // Simple LRU eviction - in practice, you'd want a more sophisticated approach
    if (isCacheFull()) {
        std::lock_guard<std::mutex> lock(tile_mutex);
        if (tile_cache.size() > config.cache_size_mb / 10) { // Rough estimate
            auto it = tile_cache.begin();
            tile_cache.erase(it);
        }
    }
}

bool FGCom_TerrainElevationManager::isCacheFull() const {
    return getCacheSize() > config.cache_size_mb / 10; // Rough estimate
}

void FGCom_TerrainElevationManager::logError(const std::string& error) const {
    std::cerr << "[FGCom_TerrainElevationManager] " << error << std::endl;
    setLastError(error);
}

// =============================================================================
// FGCom_ASTERGDEMLoader Implementation
// =============================================================================

FGCom_ASTERGDEMLoader::FGCom_ASTERGDEMLoader(const std::string& data_path, const std::string& download_url)
    : data_path(data_path), download_url(download_url), download_enabled(true) {
}

FGCom_ASTERGDEMLoader::~FGCom_ASTERGDEMLoader() {
}

bool FGCom_ASTERGDEMLoader::loadTile(double latitude, double longitude, ASTERGDEMTile& tile) {
    std::string tile_path = getTilePath(latitude, longitude);
    
    if (!std::filesystem::exists(tile_path)) {
        if (download_enabled.load()) {
            std::string tile_name = getTileFilename(latitude, longitude);
            if (downloadTile(tile_name)) {
                return loadTile(latitude, longitude, tile);
            }
        }
        return false;
    }
    
    // Load tile metadata
    tile.filename = getTileFilename(latitude, longitude);
    tile.min_lat = std::floor(latitude);
    tile.max_lat = tile.min_lat + 1.0;
    tile.min_lon = std::floor(longitude);
    tile.max_lon = tile.min_lon + 1.0;
    tile.file_path = tile_path;
    tile.loaded = true;
    tile.file_size_bytes = std::filesystem::file_size(tile_path);
    
    return true;
}

bool FGCom_ASTERGDEMLoader::downloadTile(const std::string& tile_name) {
    if (!download_enabled.load()) {
        return false;
    }
    
    std::string url = constructDownloadURL(tile_name);
    std::string filepath = data_path + "/" + tile_name + ".tif";
    
    return downloadFile(url, filepath);
}

std::vector<std::string> FGCom_ASTERGDEMLoader::getAvailableTiles() const {
    std::vector<std::string> tiles;
    
    try {
        for (const auto& entry : std::filesystem::directory_iterator(data_path)) {
            if (entry.is_regular_file() && entry.path().extension() == ".tif") {
                tiles.push_back(entry.path().stem().string());
            }
        }
    } catch (const std::exception& e) {
        logError("Failed to list available tiles: " + std::string(e.what()));
    }
    
    return tiles;
}

bool FGCom_ASTERGDEMLoader::isTileAvailable(double latitude, double longitude) const {
    std::string tile_path = getTilePath(latitude, longitude);
    return std::filesystem::exists(tile_path);
}

std::string FGCom_ASTERGDEMLoader::getTilePath(double latitude, double longitude) const {
    return data_path + "/" + getTileFilename(latitude, longitude);
}

std::string FGCom_ASTERGDEMLoader::getTileFilename(double latitude, double longitude) const {
    int lat_tile = static_cast<int>(std::floor(latitude));
    int lon_tile = static_cast<int>(std::floor(longitude));
    
    std::string lat_str = (lat_tile >= 0) ? "N" + std::to_string(lat_tile) : "S" + std::to_string(-lat_tile);
    std::string lon_str = (lon_tile >= 0) ? "E" + std::to_string(lon_tile) : "W" + std::to_string(-lon_tile);
    
    return lat_str + lon_str;
}

bool FGCom_ASTERGDEMLoader::createDataDirectory() {
    try {
        if (!std::filesystem::exists(data_path)) {
            std::filesystem::create_directories(data_path);
        }
        return true;
    } catch (const std::exception& e) {
        logError("Failed to create data directory: " + std::string(e.what()));
        return false;
    }
}

std::string FGCom_ASTERGDEMLoader::getLastError() const {
    return last_error;
}

void FGCom_ASTERGDEMLoader::setLastError(const std::string& error) {
    last_error = error;
}

std::string FGCom_ASTERGDEMLoader::constructDownloadURL(const std::string& tile_name) const {
    return download_url + tile_name + ".tif";
}

bool FGCom_ASTERGDEMLoader::downloadFile(const std::string& url, const std::string& filepath) {
    // Simplified download implementation without CURL dependency
    // In a real implementation, you would use a proper HTTP client library
    
    setLastError("Download functionality requires CURL library - not implemented in this build");
    return false;
    
    // TODO: Implement proper HTTP download using available libraries
    // For now, return false to indicate download is not available
}

void FGCom_ASTERGDEMLoader::logError(const std::string& error) const {
    std::cerr << "[FGCom_ASTERGDEMLoader] " << error << std::endl;
}

// =============================================================================
// FGCom_TerrainObstructionAnalyzer Implementation
// =============================================================================

FGCom_TerrainObstructionAnalyzer::FGCom_TerrainObstructionAnalyzer(double fresnel_clearance, 
                                                                 bool enable_diffraction,
                                                                 bool enable_fresnel)
    : fresnel_clearance_percent(fresnel_clearance), enable_diffraction(enable_diffraction),
      enable_fresnel_zone(enable_fresnel) {
}

ObstructionResult FGCom_TerrainObstructionAnalyzer::analyzeObstruction(const TerrainProfile& profile,
                                                                       double alt1, double alt2,
                                                                       double frequency_mhz) {
    ObstructionResult result;
    
    if (profile.points.empty()) {
        return result;
    }
    
    // Check line of sight
    result.blocked = !isLineOfSightClear(profile, alt1, alt2);
    
    if (result.blocked) {
        result.obstruction_height_m = profile.obstruction_height_m;
        result.obstruction_distance_km = profile.obstruction_distance_km;
        result.obstruction_type = "mountain"; // Simplified classification
        
        // Calculate terrain loss
        result.terrain_loss_db = 20.0 * std::log10(profile.obstruction_height_m / 10.0);
        
        // Calculate diffraction loss if enabled
        if (enable_diffraction) {
            result.diffraction_loss_db = calculateDiffractionLoss(profile.obstruction_height_m, 
                                                                profile.obstruction_distance_km, 
                                                                frequency_mhz);
        }
    }
    
    // Check Fresnel zone clearance
    if (enable_fresnel_zone) {
        FresnelZoneResult fresnel = calculateFresnelZone(profile, alt1, alt2, frequency_mhz);
        result.fresnel_zone_clear = fresnel.zone_clear;
        result.fresnel_clearance_percent = fresnel.clearance_percent;
    }
    
    return result;
}

FresnelZoneResult FGCom_TerrainObstructionAnalyzer::calculateFresnelZone(const TerrainProfile& profile,
                                                                         double alt1, double alt2,
                                                                         double frequency_mhz) {
    FresnelZoneResult result;
    
    if (profile.points.empty()) {
        return result;
    }
    
    // Calculate total distance
    double total_distance_km = profile.points.back().distance_km;
    
    // Calculate Fresnel radius
    result.fresnel_radius_m = calculateFresnelRadius(total_distance_km, frequency_mhz);
    
    // Calculate required clearance
    result.required_clearance_m = calculateRequiredClearance(profile, alt1, alt2);
    
    // Check clearance
    result.actual_clearance_m = result.required_clearance_m;
    result.clearance_percent = (result.actual_clearance_m / result.fresnel_radius_m) * 100.0;
    result.zone_clear = result.clearance_percent >= (fresnel_clearance_percent * 100.0);
    
    return result;
}

double FGCom_TerrainObstructionAnalyzer::calculateDiffractionLoss(double obstruction_height_m, 
                                                                double distance_km,
                                                                double frequency_mhz) {
    if (!enable_diffraction) {
        return 0.0;
    }
    
    // Simplified diffraction loss calculation
    double wavelength_m = 300.0 / frequency_mhz; // Speed of light / frequency
    double fresnel_radius = std::sqrt(wavelength_m * distance_km * 1000.0 / 2.0);
    
    double v = obstruction_height_m / fresnel_radius;
    
    if (v < -0.8) {
        return 0.0; // No obstruction
    } else if (v < 0.0) {
        return 6.0 + 8.0 * v; // Partial obstruction
    } else {
        return 6.0 + 8.0 * v + 8.0 * v * v; // Full obstruction
    }
}

bool FGCom_TerrainObstructionAnalyzer::isLineOfSightClear(const TerrainProfile& profile, 
                                                         double alt1, double alt2) {
    if (profile.points.empty()) {
        return true;
    }
    
    double total_distance_km = profile.points.back().distance_km;
    
    for (const auto& point : profile.points) {
        // Calculate expected elevation at this point
        double fraction = point.distance_km / total_distance_km;
        double expected_elevation = alt1 + (alt2 - alt1) * fraction;
        
        // Check if terrain is above the line of sight
        if (point.elevation_m > expected_elevation + 10.0) { // 10m threshold
            return false;
        }
    }
    
    return true;
}

double FGCom_TerrainObstructionAnalyzer::calculateFresnelRadius(double distance_km, double frequency_mhz) const {
    double wavelength_m = 300.0 / frequency_mhz;
    return std::sqrt(wavelength_m * distance_km * 1000.0 / 2.0);
}

double FGCom_TerrainObstructionAnalyzer::calculateRequiredClearance(const TerrainProfile& profile, 
                                                                   double alt1, double alt2) const {
    double max_clearance = 0.0;
    
    for (const auto& point : profile.points) {
        double fraction = point.distance_km / profile.points.back().distance_km;
        double expected_elevation = alt1 + (alt2 - alt1) * fraction;
        double clearance = point.elevation_m - expected_elevation;
        max_clearance = std::max(max_clearance, clearance);
    }
    
    return max_clearance;
}

bool FGCom_TerrainObstructionAnalyzer::checkFresnelZoneClearance(const TerrainProfile& profile, 
                                                               double alt1, double alt2,
                                                               double frequency_mhz) const {
    // Create a non-const reference to call the non-const method
    FGCom_TerrainObstructionAnalyzer* non_const_this = const_cast<FGCom_TerrainObstructionAnalyzer*>(this);
    FresnelZoneResult fresnel = non_const_this->calculateFresnelZone(profile, alt1, alt2, frequency_mhz);
    return fresnel.zone_clear;
}
