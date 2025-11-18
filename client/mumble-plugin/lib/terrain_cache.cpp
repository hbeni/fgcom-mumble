#include "terrain_cache.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>

namespace FGCom_TerrainEnvironmental {

    // CacheEntry implementation
    CacheEntry::CacheEntry(const std::string& data, std::chrono::milliseconds ttl)
        : data(data), timestamp(std::chrono::steady_clock::now()), ttl(ttl) {
    }

    bool CacheEntry::isValid() const noexcept {
        auto now = std::chrono::steady_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(now - timestamp);
        return age < ttl;
    }

    // TerrainCache implementation
    TerrainCache::TerrainCache(size_t maxSize, std::chrono::milliseconds defaultTtl)
        : max_size_(maxSize), default_ttl_(defaultTtl), hits_(0), misses_(0), evictions_(0) {
    }

    TerrainCache::TerrainCache(TerrainCache&& other) noexcept
        : cache_map_(std::move(other.cache_map_)),
          max_size_(other.max_size_.load()),
          default_ttl_(other.default_ttl_),
          hits_(other.hits_.load()),
          misses_(other.misses_.load()),
          evictions_(other.evictions_.load()) {
    }

    TerrainCache& TerrainCache::operator=(TerrainCache&& other) noexcept {
        if (this != &other) {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            cache_map_ = std::move(other.cache_map_);
            max_size_ = other.max_size_.load();
            default_ttl_ = other.default_ttl_;
            hits_ = other.hits_.load();
            misses_ = other.misses_.load();
            evictions_ = other.evictions_.load();
        }
        return *this;
    }

    bool TerrainCache::store(const std::string& key, const std::string& data, std::chrono::milliseconds ttl) {
        if (key.empty() || data.empty()) {
            return false;
        }
        
        std::lock_guard<std::mutex> lock(cache_mutex_);
        
        // Use default TTL if not specified
        if (ttl.count() == 0) {
            ttl = default_ttl_;
        }
        
        // Check if we need to evict entries
        while (cache_map_.size() >= max_size_.load()) {
            if (!evictLRU()) {
                return false; // Failed to evict
            }
        }
        
        // Store the entry
        cache_map_[key] = CacheEntry(data, ttl);
        return true;
    }

    std::string TerrainCache::retrieve(const std::string& key) {
        if (key.empty()) {
            misses_++;
            return "";
        }
        
        std::lock_guard<std::mutex> lock(cache_mutex_);
        
        auto it = cache_map_.find(key);
        if (it == cache_map_.end()) {
            misses_++;
            return "";
        }
        
        // Check if entry is still valid
        if (!it->second.isValid()) {
            cache_map_.erase(it);
            misses_++;
            return "";
        }
        
        hits_++;
        updateAccessTime(key);
        return it->second.data;
    }

    bool TerrainCache::exists(const std::string& key) const {
        if (key.empty()) {
            return false;
        }
        
        std::lock_guard<std::mutex> lock(cache_mutex_);
        
        auto it = cache_map_.find(key);
        if (it == cache_map_.end()) {
            return false;
        }
        
        return it->second.isValid();
    }

    bool TerrainCache::remove(const std::string& key) {
        if (key.empty()) {
            return false;
        }
        
        std::lock_guard<std::mutex> lock(cache_mutex_);
        
        auto it = cache_map_.find(key);
        if (it == cache_map_.end()) {
            return false;
        }
        
        cache_map_.erase(it);
        return true;
    }

    void TerrainCache::clear() noexcept {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        cache_map_.clear();
    }

    std::string TerrainCache::getStatistics() const {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        
        uint64_t total_requests = hits_.load() + misses_.load();
        double hit_rate = total_requests > 0 ? static_cast<double>(hits_.load()) / total_requests : 0.0;
        
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2);
        oss << "{\n";
        oss << "  \"cache_size\": " << cache_map_.size() << ",\n";
        oss << "  \"max_size\": " << max_size_.load() << ",\n";
        oss << "  \"hits\": " << hits_.load() << ",\n";
        oss << "  \"misses\": " << misses_.load() << ",\n";
        oss << "  \"evictions\": " << evictions_.load() << ",\n";
        oss << "  \"hit_rate\": " << hit_rate << ",\n";
        oss << "  \"default_ttl_ms\": " << default_ttl_.count() << "\n";
        oss << "}";
        
        return oss.str();
    }

    size_t TerrainCache::cleanExpiredEntries() {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        
        size_t cleaned = 0;
        auto it = cache_map_.begin();
        
        while (it != cache_map_.end()) {
            if (!it->second.isValid()) {
                it = cache_map_.erase(it);
                cleaned++;
            } else {
                ++it;
            }
        }
        
        return cleaned;
    }

    size_t TerrainCache::size() const noexcept {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        return cache_map_.size();
    }

    bool TerrainCache::empty() const noexcept {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        return cache_map_.empty();
    }

    void TerrainCache::setMaxSize(size_t maxSize) noexcept {
        max_size_ = maxSize;
    }

    void TerrainCache::setDefaultTtl(std::chrono::milliseconds ttl) noexcept {
        default_ttl_ = ttl;
    }

    bool TerrainCache::evictLRU() {
        if (cache_map_.empty()) {
            return false;
        }
        
        // Simple LRU: remove the first entry (oldest access time)
        auto it = cache_map_.begin();
        cache_map_.erase(it);
        evictions_++;
        return true;
    }

    void TerrainCache::updateAccessTime(const std::string& key) {
        // In a more sophisticated implementation, this would update access times
        // For now, we use the simple approach of moving to end
        auto it = cache_map_.find(key);
        if (it != cache_map_.end()) {
            auto entry = it->second;
            cache_map_.erase(it);
            cache_map_[key] = entry;
        }
    }

    // TerrainCacheKeyGenerator implementation
    std::string TerrainCacheKeyGenerator::generateLOSKey(double txLat, double txLon, double txAlt,
                                                       double rxLat, double rxLon, double rxAlt) {
        std::ostringstream oss;
        oss << "los_" << std::fixed << std::setprecision(6)
            << normalizeCoordinate(txLat) << "_" << normalizeCoordinate(txLon) << "_" << normalizeCoordinate(txAlt)
            << "_" << normalizeCoordinate(rxLat) << "_" << normalizeCoordinate(rxLon) << "_" << normalizeCoordinate(rxAlt);
        return oss.str();
    }

    std::string TerrainCacheKeyGenerator::generateAltitudeKey(double lat, double lon) {
        std::ostringstream oss;
        oss << "alt_" << std::fixed << std::setprecision(6)
            << normalizeCoordinate(lat) << "_" << normalizeCoordinate(lon);
        return oss.str();
    }

    std::string TerrainCacheKeyGenerator::generateEnvironmentalKey(double lat, double lon) {
        std::ostringstream oss;
        oss << "env_" << std::fixed << std::setprecision(6)
            << normalizeCoordinate(lat) << "_" << normalizeCoordinate(lon);
        return oss.str();
    }

    std::string TerrainCacheKeyGenerator::generateNoiseFloorKey(double lat, double lon, double frequency,
                                                              const std::string& timeOfDay, const std::string& season) {
        std::ostringstream oss;
        oss << "noise_" << std::fixed << std::setprecision(6)
            << normalizeCoordinate(lat) << "_" << normalizeCoordinate(lon) << "_" << normalizeCoordinate(frequency)
            << "_" << timeOfDay << "_" << season;
        return oss.str();
    }

    double TerrainCacheKeyGenerator::normalizeCoordinate(double coord, int precision) {
        // Round to specified precision
        double factor = std::pow(10.0, precision);
        return std::round(coord * factor) / factor;
    }

} // namespace FGCom_TerrainEnvironmental
