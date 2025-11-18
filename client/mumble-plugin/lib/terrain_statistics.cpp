#include "terrain_statistics.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace FGCom_TerrainEnvironmental {

    // TerrainStatistics implementation
    TerrainStatistics::TerrainStatistics()
        : los_checks_total_(0), los_checks_successful_(0),
          altitude_queries_total_(0), altitude_queries_successful_(0),
          environmental_queries_total_(0), environmental_queries_successful_(0),
          noise_calculations_total_(0), noise_calculations_successful_(0),
          los_checks_total_time_ms_(0), altitude_queries_total_time_ms_(0),
          environmental_queries_total_time_ms_(0), noise_calculations_total_time_ms_(0),
          cache_hits_(0), cache_misses_(0),
          start_time_(std::chrono::steady_clock::now()) {
    }

    void TerrainStatistics::recordLOSCheck(std::chrono::milliseconds duration, bool success) noexcept {
        los_checks_total_++;
        if (success) {
            los_checks_successful_++;
        }
        los_checks_total_time_ms_ += duration.count();
    }

    void TerrainStatistics::recordAltitudeQuery(std::chrono::milliseconds duration, bool success) noexcept {
        altitude_queries_total_++;
        if (success) {
            altitude_queries_successful_++;
        }
        altitude_queries_total_time_ms_ += duration.count();
    }

    void TerrainStatistics::recordEnvironmentalQuery(std::chrono::milliseconds duration, bool success) noexcept {
        environmental_queries_total_++;
        if (success) {
            environmental_queries_successful_++;
        }
        environmental_queries_total_time_ms_ += duration.count();
    }

    void TerrainStatistics::recordNoiseFloorCalculation(std::chrono::milliseconds duration, bool success) noexcept {
        noise_calculations_total_++;
        if (success) {
            noise_calculations_successful_++;
        }
        noise_calculations_total_time_ms_ += duration.count();
    }

    void TerrainStatistics::recordCacheHit() noexcept {
        cache_hits_++;
    }

    void TerrainStatistics::recordCacheMiss() noexcept {
        cache_misses_++;
    }

    void TerrainStatistics::recordError(const std::string& errorType) noexcept {
        std::lock_guard<std::mutex> lock(error_mutex_);
        error_counts_[errorType]++;
    }

    std::string TerrainStatistics::getStatistics() const {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2);
        oss << "{\n";
        oss << "  \"los_checks\": {\n";
        oss << "    \"total\": " << los_checks_total_.load() << ",\n";
        oss << "    \"successful\": " << los_checks_successful_.load() << ",\n";
        oss << "    \"success_rate\": " << calculateSuccessRate(los_checks_successful_.load(), los_checks_total_.load()) << ",\n";
        oss << "    \"avg_time_ms\": " << calculateAverageTime(los_checks_total_time_ms_.load(), los_checks_total_.load()) << "\n";
        oss << "  },\n";
        oss << "  \"altitude_queries\": {\n";
        oss << "    \"total\": " << altitude_queries_total_.load() << ",\n";
        oss << "    \"successful\": " << altitude_queries_successful_.load() << ",\n";
        oss << "    \"success_rate\": " << calculateSuccessRate(altitude_queries_successful_.load(), altitude_queries_total_.load()) << ",\n";
        oss << "    \"avg_time_ms\": " << calculateAverageTime(altitude_queries_total_time_ms_.load(), altitude_queries_total_.load()) << "\n";
        oss << "  },\n";
        oss << "  \"environmental_queries\": {\n";
        oss << "    \"total\": " << environmental_queries_total_.load() << ",\n";
        oss << "    \"successful\": " << environmental_queries_successful_.load() << ",\n";
        oss << "    \"success_rate\": " << calculateSuccessRate(environmental_queries_successful_.load(), environmental_queries_total_.load()) << ",\n";
        oss << "    \"avg_time_ms\": " << calculateAverageTime(environmental_queries_total_time_ms_.load(), environmental_queries_total_.load()) << "\n";
        oss << "  },\n";
        oss << "  \"noise_calculations\": {\n";
        oss << "    \"total\": " << noise_calculations_total_.load() << ",\n";
        oss << "    \"successful\": " << noise_calculations_successful_.load() << ",\n";
        oss << "    \"success_rate\": " << calculateSuccessRate(noise_calculations_successful_.load(), noise_calculations_total_.load()) << ",\n";
        oss << "    \"avg_time_ms\": " << calculateAverageTime(noise_calculations_total_time_ms_.load(), noise_calculations_total_.load()) << "\n";
        oss << "  },\n";
        oss << "  \"cache\": {\n";
        oss << "    \"hits\": " << cache_hits_.load() << ",\n";
        oss << "    \"misses\": " << cache_misses_.load() << ",\n";
        oss << "    \"hit_rate\": " << getCacheHitRate() << "\n";
        oss << "  },\n";
        oss << "  \"uptime_ms\": " << getUptime().count() << "\n";
        oss << "}";
        
        return oss.str();
    }

    std::string TerrainStatistics::getPerformanceSummary() const {
        std::ostringstream oss;
        oss << "Terrain Statistics Summary:\n";
        oss << "LOS Checks: " << los_checks_total_.load() << " (success rate: " 
            << std::fixed << std::setprecision(1) 
            << calculateSuccessRate(los_checks_successful_.load(), los_checks_total_.load()) * 100 << "%)\n";
        oss << "Altitude Queries: " << altitude_queries_total_.load() << " (success rate: " 
            << calculateSuccessRate(altitude_queries_successful_.load(), altitude_queries_total_.load()) * 100 << "%)\n";
        oss << "Environmental Queries: " << environmental_queries_total_.load() << " (success rate: " 
            << calculateSuccessRate(environmental_queries_successful_.load(), environmental_queries_total_.load()) * 100 << "%)\n";
        oss << "Noise Calculations: " << noise_calculations_total_.load() << " (success rate: " 
            << calculateSuccessRate(noise_calculations_successful_.load(), noise_calculations_total_.load()) * 100 << "%)\n";
        oss << "Cache Hit Rate: " << getCacheHitRate() * 100 << "%\n";
        oss << "Uptime: " << getUptime().count() << " ms";
        
        return oss.str();
    }

    void TerrainStatistics::reset() noexcept {
        los_checks_total_ = 0;
        los_checks_successful_ = 0;
        altitude_queries_total_ = 0;
        altitude_queries_successful_ = 0;
        environmental_queries_total_ = 0;
        environmental_queries_successful_ = 0;
        noise_calculations_total_ = 0;
        noise_calculations_successful_ = 0;
        los_checks_total_time_ms_ = 0;
        altitude_queries_total_time_ms_ = 0;
        environmental_queries_total_time_ms_ = 0;
        noise_calculations_total_time_ms_ = 0;
        cache_hits_ = 0;
        cache_misses_ = 0;
        
        std::lock_guard<std::mutex> lock(error_mutex_);
        error_counts_.clear();
    }

    std::vector<uint64_t> TerrainStatistics::getOperationCounts() const {
        return {
            los_checks_total_.load(),
            altitude_queries_total_.load(),
            environmental_queries_total_.load(),
            noise_calculations_total_.load()
        };
    }

    std::vector<double> TerrainStatistics::getAverageOperationTimes() const {
        return {
            calculateAverageTime(los_checks_total_time_ms_.load(), los_checks_total_.load()),
            calculateAverageTime(altitude_queries_total_time_ms_.load(), altitude_queries_total_.load()),
            calculateAverageTime(environmental_queries_total_time_ms_.load(), environmental_queries_total_.load()),
            calculateAverageTime(noise_calculations_total_time_ms_.load(), noise_calculations_total_.load())
        };
    }

    std::vector<double> TerrainStatistics::getSuccessRates() const {
        return {
            calculateSuccessRate(los_checks_successful_.load(), los_checks_total_.load()),
            calculateSuccessRate(altitude_queries_successful_.load(), altitude_queries_total_.load()),
            calculateSuccessRate(environmental_queries_successful_.load(), environmental_queries_total_.load()),
            calculateSuccessRate(noise_calculations_successful_.load(), noise_calculations_total_.load())
        };
    }

    double TerrainStatistics::getCacheHitRate() const noexcept {
        uint64_t total = cache_hits_.load() + cache_misses_.load();
        return total > 0 ? static_cast<double>(cache_hits_.load()) / total : 0.0;
    }

    uint64_t TerrainStatistics::getTotalOperations() const noexcept {
        return los_checks_total_.load() + altitude_queries_total_.load() + 
               environmental_queries_total_.load() + noise_calculations_total_.load();
    }

    std::chrono::milliseconds TerrainStatistics::getUptime() const noexcept {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_);
    }

    double TerrainStatistics::calculateAverageTime(uint64_t totalTime, uint64_t count) const noexcept {
        return count > 0 ? static_cast<double>(totalTime) / count : 0.0;
    }

    double TerrainStatistics::calculateSuccessRate(uint64_t successful, uint64_t total) const noexcept {
        return total > 0 ? static_cast<double>(successful) / total : 0.0;
    }

    // TerrainOperationRecorder implementation
    TerrainOperationRecorder::TerrainOperationRecorder(TerrainStatistics& stats, const std::string& operationType)
        : statistics_(stats), operation_type_(operationType), start_time_(std::chrono::steady_clock::now()), success_(false) {
    }

    TerrainOperationRecorder::~TerrainOperationRecorder() {
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time_);
        
        if (operation_type_ == "los_check") {
            statistics_.recordLOSCheck(duration, success_);
        } else if (operation_type_ == "altitude_query") {
            statistics_.recordAltitudeQuery(duration, success_);
        } else if (operation_type_ == "environmental_query") {
            statistics_.recordEnvironmentalQuery(duration, success_);
        } else if (operation_type_ == "noise_calculation") {
            statistics_.recordNoiseFloorCalculation(duration, success_);
        }
    }

    void TerrainOperationRecorder::markSuccess() noexcept {
        success_ = true;
    }

    void TerrainOperationRecorder::markFailure(const std::string& errorType) noexcept {
        success_ = false;
        statistics_.recordError(errorType);
    }

} // namespace FGCom_TerrainEnvironmental
