#ifndef TERRAIN_STATISTICS_H
#define TERRAIN_STATISTICS_H

#include <atomic>
#include <chrono>
#include <string>
#include <mutex>
#include <vector>
#include <unordered_map>

namespace FGCom_TerrainEnvironmental {

    /**
     * @brief Performance statistics for terrain operations
     * 
     * Thread-safe collection of performance metrics with atomic operations.
     * Provides separation of concerns by isolating statistics tracking.
     */
    class TerrainStatistics {
    public:
        explicit TerrainStatistics();
        ~TerrainStatistics() = default;

        // Non-copyable, non-movable
        TerrainStatistics(const TerrainStatistics&) = delete;
        TerrainStatistics& operator=(const TerrainStatistics&) = delete;
        TerrainStatistics(TerrainStatistics&&) = delete;
        TerrainStatistics& operator=(TerrainStatistics&&) = delete;

        /**
         * @brief Record LOS check operation
         * 
         * @param duration Operation duration
         * @param success Whether operation was successful
         */
        void recordLOSCheck(std::chrono::milliseconds duration, bool success) noexcept;

        /**
         * @brief Record altitude query operation
         * 
         * @param duration Operation duration
         * @param success Whether operation was successful
         */
        void recordAltitudeQuery(std::chrono::milliseconds duration, bool success) noexcept;

        /**
         * @brief Record environmental query operation
         * 
         * @param duration Operation duration
         * @param success Whether operation was successful
         */
        void recordEnvironmentalQuery(std::chrono::milliseconds duration, bool success) noexcept;

        /**
         * @brief Record noise floor calculation operation
         * 
         * @param duration Operation duration
         * @param success Whether operation was successful
         */
        void recordNoiseFloorCalculation(std::chrono::milliseconds duration, bool success) noexcept;

        /**
         * @brief Record cache hit
         */
        void recordCacheHit() noexcept;

        /**
         * @brief Record cache miss
         */
        void recordCacheMiss() noexcept;

        /**
         * @brief Record error
         * 
         * @param errorType Type of error
         */
        void recordError(const std::string& errorType) noexcept;

        /**
         * @brief Get statistics as JSON string
         * 
         * @return std::string Statistics in JSON format
         */
        std::string getStatistics() const;

        /**
         * @brief Get performance summary
         * 
         * @return std::string Performance summary
         */
        std::string getPerformanceSummary() const;

        /**
         * @brief Reset all statistics
         */
        void reset() noexcept;

        /**
         * @brief Get operation counts
         * 
         * @return std::vector<uint64_t> Vector of operation counts
         */
        std::vector<uint64_t> getOperationCounts() const;

        /**
         * @brief Get average operation times
         * 
         * @return std::vector<double> Vector of average times in milliseconds
         */
        std::vector<double> getAverageOperationTimes() const;

        /**
         * @brief Get success rates
         * 
         * @return std::vector<double> Vector of success rates (0.0-1.0)
         */
        std::vector<double> getSuccessRates() const;

        /**
         * @brief Get cache hit rate
         * 
         * @return double Cache hit rate (0.0-1.0)
         */
        double getCacheHitRate() const noexcept;

        /**
         * @brief Get total operations count
         * 
         * @return uint64_t Total number of operations
         */
        uint64_t getTotalOperations() const noexcept;

        /**
         * @brief Get uptime
         * 
         * @return std::chrono::milliseconds Uptime in milliseconds
         */
        std::chrono::milliseconds getUptime() const noexcept;

    private:
        // Operation counters
        std::atomic<uint64_t> los_checks_total_;
        std::atomic<uint64_t> los_checks_successful_;
        std::atomic<uint64_t> altitude_queries_total_;
        std::atomic<uint64_t> altitude_queries_successful_;
        std::atomic<uint64_t> environmental_queries_total_;
        std::atomic<uint64_t> environmental_queries_successful_;
        std::atomic<uint64_t> noise_calculations_total_;
        std::atomic<uint64_t> noise_calculations_successful_;

        // Timing data
        std::atomic<uint64_t> los_checks_total_time_ms_;
        std::atomic<uint64_t> altitude_queries_total_time_ms_;
        std::atomic<uint64_t> environmental_queries_total_time_ms_;
        std::atomic<uint64_t> noise_calculations_total_time_ms_;

        // Cache statistics
        std::atomic<uint64_t> cache_hits_;
        std::atomic<uint64_t> cache_misses_;

        // Error statistics
        mutable std::mutex error_mutex_;
        std::unordered_map<std::string, uint64_t> error_counts_;

        // Start time for uptime calculation
        std::chrono::steady_clock::time_point start_time_;

        /**
         * @brief Calculate average time for operation
         * 
         * @param totalTime Total time in milliseconds
         * @param count Number of operations
         * @return double Average time in milliseconds
         */
        double calculateAverageTime(uint64_t totalTime, uint64_t count) const noexcept;

        /**
         * @brief Calculate success rate
         * 
         * @param successful Number of successful operations
         * @param total Total number of operations
         * @return double Success rate (0.0-1.0)
         */
        double calculateSuccessRate(uint64_t successful, uint64_t total) const noexcept;
    };

    /**
     * @brief RAII statistics recorder
     * 
     * Automatically records operation duration and success/failure.
     */
    class TerrainOperationRecorder {
    public:
        explicit TerrainOperationRecorder(TerrainStatistics& stats, const std::string& operationType);
        ~TerrainOperationRecorder();

        // Non-copyable, non-movable
        TerrainOperationRecorder(const TerrainOperationRecorder&) = delete;
        TerrainOperationRecorder& operator=(const TerrainOperationRecorder&) = delete;
        TerrainOperationRecorder(TerrainOperationRecorder&&) = delete;
        TerrainOperationRecorder& operator=(TerrainOperationRecorder&&) = delete;

        /**
         * @brief Mark operation as successful
         */
        void markSuccess() noexcept;

        /**
         * @brief Mark operation as failed
         * 
         * @param errorType Type of error
         */
        void markFailure(const std::string& errorType) noexcept;

    private:
        TerrainStatistics& statistics_;
        std::string operation_type_;
        std::chrono::steady_clock::time_point start_time_;
        bool success_;
    };

} // namespace FGCom_TerrainEnvironmental

#endif // TERRAIN_STATISTICS_H
