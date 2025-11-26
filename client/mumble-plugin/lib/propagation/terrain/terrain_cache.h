#ifndef TERRAIN_CACHE_H
#define TERRAIN_CACHE_H

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <atomic>
#include <memory>

namespace FGCom_TerrainEnvironmental {

    /**
     * @brief Thread-safe cache entry with timestamp
     * 
     * Stores cached data with creation timestamp for expiration.
     */
    struct CacheEntry {
        std::string data;
        std::chrono::steady_clock::time_point timestamp;
        std::chrono::milliseconds ttl;
        
        CacheEntry() = default;
        CacheEntry(const std::string& data, std::chrono::milliseconds ttl);
        
        /**
         * @brief Check if cache entry is valid
         * 
         * @return bool True if entry is still valid
         */
        bool isValid() const noexcept;
    };

    /**
     * @brief Thread-safe cache for terrain and environmental data
     * 
     * Implements LRU cache with TTL support and thread-safe operations.
     * Provides separation of concerns by isolating caching logic.
     */
    class TerrainCache {
    public:
        explicit TerrainCache(size_t maxSize = 1000, std::chrono::milliseconds defaultTtl = std::chrono::minutes(5));
        ~TerrainCache() = default;

        // Non-copyable, movable
        TerrainCache(const TerrainCache&) = delete;
        TerrainCache& operator=(const TerrainCache&) = delete;
        TerrainCache(TerrainCache&&) noexcept;
        TerrainCache& operator=(TerrainCache&&) noexcept;

        /**
         * @brief Store data in cache
         * 
         * @param key Cache key
         * @param data Data to cache
         * @param ttl Time to live (optional, uses default if not specified)
         * @return bool True if stored successfully
         */
        bool store(const std::string& key, const std::string& data, 
                  std::chrono::milliseconds ttl = std::chrono::milliseconds(0));

        /**
         * @brief Retrieve data from cache
         * 
         * @param key Cache key
         * @return std::string Cached data (empty if not found or expired)
         */
        std::string retrieve(const std::string& key);

        /**
         * @brief Check if key exists in cache
         * 
         * @param key Cache key
         * @return bool True if key exists and is valid
         */
        bool exists(const std::string& key) const;

        /**
         * @brief Remove entry from cache
         * 
         * @param key Cache key
         * @return bool True if removed successfully
         */
        bool remove(const std::string& key);

        /**
         * @brief Clear all cache entries
         */
        void clear() noexcept;

        /**
         * @brief Get cache statistics
         * 
         * @return std::string Cache statistics as JSON
         */
        std::string getStatistics() const;

        /**
         * @brief Clean expired entries
         * 
         * @return size_t Number of entries cleaned
         */
        size_t cleanExpiredEntries();

        /**
         * @brief Get cache size
         * 
         * @return size_t Number of entries in cache
         */
        size_t size() const noexcept;

        /**
         * @brief Check if cache is empty
         * 
         * @return bool True if cache is empty
         */
        bool empty() const noexcept;

        /**
         * @brief Set maximum cache size
         * 
         * @param maxSize Maximum number of entries
         */
        void setMaxSize(size_t maxSize) noexcept;

        /**
         * @brief Set default TTL for new entries
         * 
         * @param ttl Default time to live
         */
        void setDefaultTtl(std::chrono::milliseconds ttl) noexcept;

    private:
        mutable std::mutex cache_mutex_;
        std::unordered_map<std::string, CacheEntry> cache_map_;
        std::atomic<size_t> max_size_;
        std::chrono::milliseconds default_ttl_;
        
        // Statistics
        mutable std::atomic<uint64_t> hits_;
        mutable std::atomic<uint64_t> misses_;
        mutable std::atomic<uint64_t> evictions_;

        /**
         * @brief Evict least recently used entry
         * 
         * @return bool True if eviction successful
         */
        bool evictLRU();

        /**
         * @brief Update access time for entry
         * 
         * @param key Cache key
         */
        void updateAccessTime(const std::string& key);
    };

    /**
     * @brief Cache key generator for terrain operations
     * 
     * Generates consistent cache keys for different operations.
     */
    class TerrainCacheKeyGenerator {
    public:
        /**
         * @brief Generate cache key for LOS check
         * 
         * @param txLat Transmitter latitude
         * @param txLon Transmitter longitude
         * @param txAlt Transmitter altitude
         * @param rxLat Receiver latitude
         * @param rxLon Receiver longitude
         * @param rxAlt Receiver altitude
         * @return std::string Cache key
         */
        static std::string generateLOSKey(double txLat, double txLon, double txAlt,
                                        double rxLat, double rxLon, double rxAlt);

        /**
         * @brief Generate cache key for altitude query
         * 
         * @param lat Latitude
         * @param lon Longitude
         * @return std::string Cache key
         */
        static std::string generateAltitudeKey(double lat, double lon);

        /**
         * @brief Generate cache key for environmental query
         * 
         * @param lat Latitude
         * @param lon Longitude
         * @return std::string Cache key
         */
        static std::string generateEnvironmentalKey(double lat, double lon);

        /**
         * @brief Generate cache key for noise floor calculation
         * 
         * @param lat Latitude
         * @param lon Longitude
         * @param frequency Frequency
         * @param timeOfDay Time of day
         * @param season Season
         * @return std::string Cache key
         */
        static std::string generateNoiseFloorKey(double lat, double lon, double frequency,
                                               const std::string& timeOfDay, const std::string& season);

    private:
        /**
         * @brief Normalize coordinate for cache key
         * 
         * @param coord Coordinate value
         * @param precision Precision for rounding
         * @return double Normalized coordinate
         */
        static double normalizeCoordinate(double coord, int precision = 6);
    };

} // namespace FGCom_TerrainEnvironmental

#endif // TERRAIN_CACHE_H
