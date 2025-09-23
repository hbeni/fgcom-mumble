#ifndef FGCOM_DEBUGGING_SYSTEM_H
#define FGCOM_DEBUGGING_SYSTEM_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <fstream>
#include <chrono>
#include <memory>
#include <functional>

// Debug levels
enum class DebugLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARNING = 3,
    ERROR = 4,
    CRITICAL = 5
};

// Debug categories
enum class DebugCategory {
    GENERAL = 0,
    THREADING = 1,
    GPU_ACCELERATION = 2,
    SOLAR_DATA = 3,
    PROPAGATION = 4,
    ANTENNA_PATTERNS = 5,
    AUDIO_PROCESSING = 6,
    API_SERVER = 7,
    LIGHTNING_DATA = 8,
    WEATHER_DATA = 9,
    POWER_MANAGEMENT = 10,
    FREQUENCY_OFFSET = 11,
    BFO_SIMULATION = 12,
    FILTER_APPLICATION = 13,
    FUZZY_LOGIC = 14,
    VEHICLE_DYNAMICS = 15,
    CACHE_OPERATIONS = 16,
    NETWORK_OPERATIONS = 17,
    FILE_OPERATIONS = 18,
    MEMORY_OPERATIONS = 19,
    PERFORMANCE_MONITORING = 20
};

// Debug message structure
struct DebugMessage {
    DebugLevel level;
    DebugCategory category;
    std::string message;
    std::string source_file;
    int source_line;
    std::string function_name;
    std::chrono::system_clock::time_point timestamp;
    std::thread::id thread_id;
    std::map<std::string, std::string> context;
    
    DebugMessage() : level(DebugLevel::INFO), category(DebugCategory::GENERAL), source_line(0) {}
};

// Debug output handler interface
class IDebugOutputHandler {
public:
    virtual ~IDebugOutputHandler() = default;
    virtual void handleMessage(const DebugMessage& message) = 0;
    virtual void flush() = 0;
    virtual void close() = 0;
};

// Console debug output handler
class ConsoleDebugHandler : public IDebugOutputHandler {
private:
    std::mutex output_mutex;
    bool color_output;
    bool show_timestamp;
    bool show_thread_id;
    bool show_source_location;
    
public:
    ConsoleDebugHandler(bool color = true, bool timestamp = true, bool thread_id = true, bool source_location = true);
    virtual ~ConsoleDebugHandler() = default;
    
    void handleMessage(const DebugMessage& message) override;
    void flush() override;
    void close() override;
    
    void setColorOutput(bool enable);
    void setShowTimestamp(bool enable);
    void setShowThreadId(bool enable);
    void setShowSourceLocation(bool enable);
    
private:
    std::string getColorCode(DebugLevel level) const;
    std::string formatMessage(const DebugMessage& message) const;
};

// File debug output handler
class FileDebugHandler : public IDebugOutputHandler {
private:
    std::ofstream log_file;
    std::mutex file_mutex;
    std::string file_path;
    size_t max_file_size;
    int max_files;
    bool auto_rotate;
    
public:
    FileDebugHandler(const std::string& file_path, size_t max_size = 10 * 1024 * 1024, int max_files = 5, bool auto_rotate = true);
    virtual ~FileDebugHandler();
    
    void handleMessage(const DebugMessage& message) override;
    void flush() override;
    void close() override;
    
    void setMaxFileSize(size_t max_size);
    void setMaxFiles(int max_files);
    void setAutoRotate(bool enable);
    void rotateLogFile();
    
private:
    void checkFileSize();
    std::string formatMessage(const DebugMessage& message) const;
};

// Network debug output handler (for remote debugging)
class NetworkDebugHandler : public IDebugOutputHandler {
private:
    std::string server_host;
    int server_port;
    std::mutex network_mutex;
    bool connected;
    
public:
    NetworkDebugHandler(const std::string& host, int port);
    virtual ~NetworkDebugHandler();
    
    void handleMessage(const DebugMessage& message) override;
    void flush() override;
    void close() override;
    
    bool connect();
    void disconnect();
    bool isConnected() const;
    
private:
    std::string formatMessage(const DebugMessage& message) const;
    bool sendMessage(const std::string& message);
};

// Performance profiler
class PerformanceProfiler {
private:
    struct ProfileEntry {
        std::string name;
        std::chrono::high_resolution_clock::time_point start_time;
        std::chrono::high_resolution_clock::time_point end_time;
        std::chrono::microseconds duration;
        std::map<std::string, std::string> metadata;
    };
    
    std::map<std::string, ProfileEntry> active_profiles;
    std::vector<ProfileEntry> completed_profiles;
    std::mutex profile_mutex;
    bool enabled;
    
public:
    PerformanceProfiler();
    ~PerformanceProfiler();
    
    void startProfile(const std::string& name, const std::map<std::string, std::string>& metadata = {});
    void endProfile(const std::string& name);
    void endAllProfiles();
    
    std::vector<ProfileEntry> getCompletedProfiles() const;
    std::map<std::string, double> getAverageTimes() const;
    std::map<std::string, double> getTotalTimes() const;
    
    void enable();
    void disable();
    bool isEnabled() const;
    
    void clearProfiles();
    void generateReport() const;
    
private:
    std::chrono::microseconds getCurrentDuration(const std::string& name) const;
};

// Memory usage tracker
class MemoryUsageTracker {
private:
    struct MemoryEntry {
        std::string name;
        size_t allocated_bytes;
        size_t peak_bytes;
        std::chrono::system_clock::time_point timestamp;
        std::map<std::string, std::string> metadata;
    };
    
    std::map<std::string, MemoryEntry> memory_entries;
    std::mutex memory_mutex;
    bool enabled;
    
public:
    MemoryUsageTracker();
    ~MemoryUsageTracker();
    
    void recordAllocation(const std::string& name, size_t bytes, const std::map<std::string, std::string>& metadata = {});
    void recordDeallocation(const std::string& name, size_t bytes);
    void recordPeakUsage(const std::string& name, size_t bytes);
    
    std::map<std::string, size_t> getCurrentUsage() const;
    std::map<std::string, size_t> getPeakUsage() const;
    size_t getTotalAllocated() const;
    size_t getTotalPeak() const;
    
    void enable();
    void disable();
    bool isEnabled() const;
    
    void clearEntries();
    void generateReport() const;
    
private:
    void updateEntry(const std::string& name, size_t bytes, bool is_allocation);
};

// Main debugging system
class FGCom_DebuggingSystem {
private:
    static std::unique_ptr<FGCom_DebuggingSystem> instance;
    static std::mutex instance_mutex;
    
    std::vector<std::unique_ptr<IDebugOutputHandler>> handlers;
    std::mutex handlers_mutex;
    
    std::map<DebugCategory, DebugLevel> category_levels;
    std::map<DebugCategory, bool> category_enabled;
    std::mutex config_mutex;
    
    std::atomic<bool> system_enabled;
    std::atomic<bool> performance_profiling_enabled;
    std::atomic<bool> memory_tracking_enabled;
    
    std::unique_ptr<PerformanceProfiler> profiler;
    std::unique_ptr<MemoryUsageTracker> memory_tracker;
    
    // Statistics
    std::atomic<uint64_t> total_messages;
    std::atomic<uint64_t> messages_by_level[6]; // One for each DebugLevel
    std::atomic<uint64_t> messages_by_category[21]; // One for each DebugCategory
    
    // Private constructor for singleton
    FGCom_DebuggingSystem();
    
public:
    // Singleton access
    static FGCom_DebuggingSystem& getInstance();
    static void destroyInstance();
    
    // Message logging
    void log(DebugLevel level, DebugCategory category, const std::string& message,
             const std::string& file = "", int line = 0, const std::string& function = "",
             const std::map<std::string, std::string>& context = {});
    
    // Convenience logging methods
    void trace(DebugCategory category, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
    void debug(DebugCategory category, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
    void info(DebugCategory category, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
    void warning(DebugCategory category, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
    void error(DebugCategory category, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
    void critical(DebugCategory category, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
    
    // Handler management
    void addHandler(std::unique_ptr<IDebugOutputHandler> handler);
    void removeHandler(IDebugOutputHandler* handler);
    void clearHandlers();
    
    // Configuration
    void setCategoryLevel(DebugCategory category, DebugLevel level);
    DebugLevel getCategoryLevel(DebugCategory category) const;
    void setCategoryEnabled(DebugCategory category, bool enabled);
    bool isCategoryEnabled(DebugCategory category) const;
    
    void enableSystem();
    void disableSystem();
    bool isSystemEnabled() const;
    
    void enablePerformanceProfiling();
    void disablePerformanceProfiling();
    bool isPerformanceProfilingEnabled() const;
    
    void enableMemoryTracking();
    void disableMemoryTracking();
    bool isMemoryTrackingEnabled() const;
    
    // Performance profiling
    void startProfile(const std::string& name, const std::map<std::string, std::string>& metadata = {});
    void endProfile(const std::string& name);
    void endAllProfiles();
    
    // Memory tracking
    void recordAllocation(const std::string& name, size_t bytes, const std::map<std::string, std::string>& metadata = {});
    void recordDeallocation(const std::string& name, size_t bytes);
    void recordPeakUsage(const std::string& name, size_t bytes);
    
    // Statistics and reporting
    uint64_t getTotalMessages() const;
    uint64_t getMessagesByLevel(DebugLevel level) const;
    uint64_t getMessagesByCategory(DebugCategory category) const;
    
    void generateStatisticsReport() const;
    void generatePerformanceReport() const;
    void generateMemoryReport() const;
    void generateFullReport() const;
    
    // Configuration persistence
    bool loadConfigFromFile(const std::string& config_file);
    bool saveConfigToFile(const std::string& config_file) const;
    
    // Utility methods
    void flush();
    void close();
    
private:
    // Internal helper methods
    bool shouldLog(DebugLevel level, DebugCategory category) const;
    void updateStatistics(DebugLevel level, DebugCategory category);
    std::string formatTimestamp(const std::chrono::system_clock::time_point& timestamp) const;
    std::string debugLevelToString(DebugLevel level) const;
    std::string debugCategoryToString(DebugCategory category) const;
};

// Utility macros for easy debugging
#define FGCOM_LOG_TRACE(category, message) \
    FGCom_DebuggingSystem::getInstance().trace(category, message, __FILE__, __LINE__, __FUNCTION__)

#define FGCOM_LOG_DEBUG(category, message) \
    FGCom_DebuggingSystem::getInstance().debug(category, message, __FILE__, __LINE__, __FUNCTION__)

#define FGCOM_LOG_INFO(category, message) \
    FGCom_DebuggingSystem::getInstance().info(category, message, __FILE__, __LINE__, __FUNCTION__)

#define FGCOM_LOG_WARNING(category, message) \
    FGCom_DebuggingSystem::getInstance().warning(category, message, __FILE__, __LINE__, __FUNCTION__)

#define FGCOM_LOG_ERROR(category, message) \
    FGCom_DebuggingSystem::getInstance().error(category, message, __FILE__, __LINE__, __FUNCTION__)

#define FGCOM_LOG_CRITICAL(category, message) \
    FGCom_DebuggingSystem::getInstance().critical(category, message, __FILE__, __LINE__, __FUNCTION__)

// Performance profiling macros
#define FGCOM_PROFILE_START(name) \
    FGCom_DebuggingSystem::getInstance().startProfile(name)

#define FGCOM_PROFILE_END(name) \
    FGCom_DebuggingSystem::getInstance().endProfile(name)

#define FGCOM_PROFILE_SCOPE(name) \
    FGCom_DebuggingSystem::getInstance().startProfile(name); \
    auto _fgcom_profile_guard = [&]() { FGCom_DebuggingSystem::getInstance().endProfile(name); }; \
    std::unique_ptr<void, decltype(_fgcom_profile_guard)> _fgcom_profile_ptr(nullptr, _fgcom_profile_guard)

// Memory tracking macros
#define FGCOM_MEMORY_ALLOC(name, size) \
    FGCom_DebuggingSystem::getInstance().recordAllocation(name, size)

#define FGCOM_MEMORY_DEALLOC(name, size) \
    FGCom_DebuggingSystem::getInstance().recordDeallocation(name, size)

#define FGCOM_MEMORY_PEAK(name, size) \
    FGCom_DebuggingSystem::getInstance().recordPeakUsage(name, size)

// Conditional logging macros
#define FGCOM_IF_DEBUG(category, code) \
    if (FGCom_DebuggingSystem::getInstance().isCategoryEnabled(category)) { \
        code \
    }

#define FGCOM_IF_TRACE(category, code) \
    if (FGCom_DebuggingSystem::getInstance().getCategoryLevel(category) <= DebugLevel::TRACE) { \
        code \
    }

// Utility functions
namespace DebuggingUtils {
    // String conversion utilities
    std::string debugLevelToString(DebugLevel level);
    DebugLevel stringToDebugLevel(const std::string& str);
    std::string debugCategoryToString(DebugCategory category);
    DebugCategory stringToDebugCategory(const std::string& str);
    
    // Configuration utilities
    bool loadDebugConfigFromFile(const std::string& config_file, FGCom_DebuggingSystem& debug_system);
    bool saveDebugConfigToFile(const std::string& config_file, const FGCom_DebuggingSystem& debug_system);
    
    // Formatting utilities
    std::string formatMemorySize(size_t bytes);
    std::string formatDuration(std::chrono::microseconds duration);
    std::string formatTimestamp(const std::chrono::system_clock::time_point& timestamp);
    
    // Validation utilities
    bool isValidDebugLevel(const std::string& level);
    bool isValidDebugCategory(const std::string& category);
    std::vector<std::string> getValidDebugLevels();
    std::vector<std::string> getValidDebugCategories();
}

#endif // FGCOM_DEBUGGING_SYSTEM_H
