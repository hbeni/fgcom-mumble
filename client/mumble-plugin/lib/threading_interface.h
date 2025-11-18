#ifndef FGCOM_THREADING_INTERFACE_H
#define FGCOM_THREADING_INTERFACE_H

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>

// Forward declarations
struct fgcom_solar_conditions;
struct PropagationTask;
struct GPUComputeTask;
struct LightningStrike;
struct WeatherConditions;
struct AntennaPattern;

// Abstract interface for thread management
class IThreadManager {
public:
    virtual ~IThreadManager() = default;
    
    // Thread control
    virtual bool startAllThreads() = 0;
    virtual bool stopAllThreads() = 0;
    virtual bool startThread(const std::string& thread_name) = 0;
    virtual bool stopThread(const std::string& thread_name) = 0;
    virtual bool isThreadRunning(const std::string& thread_name) const = 0;
    
    // Data access
    virtual bool getSolarData(fgcom_solar_conditions& data) const = 0;
    virtual bool updateSolarData(const fgcom_solar_conditions& data) = 0;
    virtual bool addPropagationTask(const PropagationTask& task) = 0;
    virtual bool getCompletedPropagationTask(PropagationTask& task) = 0;
    virtual bool addGPUComputeTask(const GPUComputeTask& task) = 0;
    virtual bool getCompletedGPUComputeTask(GPUComputeTask& task) = 0;
    
    // Performance monitoring
    virtual void startMonitoring() = 0;
    virtual void stopMonitoring() = 0;
    virtual bool isMonitoringActive() const = 0;
    virtual void generatePerformanceReport() const = 0;
    
    // Error handling
    virtual void setThreadError(const std::string& thread_name, const std::string& error) = 0;
    virtual std::string getThreadError(const std::string& thread_name) const = 0;
    virtual void clearThreadError(const std::string& thread_name) = 0;
    
    // Cleanup
    virtual void shutdown() = 0;
    virtual void cleanup() = 0;
};

// Abstract interface for data processing
class IDataProcessor {
public:
    virtual ~IDataProcessor() = default;
    
    virtual bool processPropagationTask(const PropagationTask& task) = 0;
    virtual bool processGPUComputeTask(const GPUComputeTask& task) = 0;
    virtual bool processSolarData(const fgcom_solar_conditions& data) = 0;
    virtual bool processLightningData(const std::vector<LightningStrike>& strikes) = 0;
    virtual bool processWeatherData(const WeatherConditions& conditions) = 0;
    virtual bool processAntennaPattern(const AntennaPattern& pattern) = 0;
};

// Abstract interface for thread monitoring
class IThreadMonitor {
public:
    virtual ~IThreadMonitor() = default;
    
    virtual void startMonitoring() = 0;
    virtual void stopMonitoring() = 0;
    virtual bool isMonitoringActive() const = 0;
    virtual void updateThreadActivity(const std::string& thread_name) = 0;
    virtual void logThreadEvent(const std::string& thread_name, const std::string& event) = 0;
    virtual void setThreadError(const std::string& thread_name, const std::string& error) = 0;
    virtual std::string getThreadError(const std::string& thread_name) const = 0;
    virtual void generatePerformanceReport() const = 0;
};

// Abstract interface for configuration management
class IThreadingConfig {
public:
    virtual ~IThreadingConfig() = default;
    
    virtual bool loadConfigFromFile(const std::string& config_file) = 0;
    virtual bool saveConfigToFile(const std::string& config_file) const = 0;
    virtual bool validateConfiguration() const = 0;
    virtual std::vector<std::string> getConfigurationErrors() const = 0;
};

// Factory interface for creating thread managers
class IThreadManagerFactory {
public:
    virtual ~IThreadManagerFactory() = default;
    
    virtual std::unique_ptr<IThreadManager> createThreadManager() = 0;
    virtual std::unique_ptr<IDataProcessor> createDataProcessor() = 0;
    virtual std::unique_ptr<IThreadMonitor> createThreadMonitor() = 0;
    virtual std::unique_ptr<IThreadingConfig> createThreadingConfig() = 0;
};

// Thread-safe utility functions
namespace ThreadingUtils {
    // Thread-safe data access helpers
    template<typename T>
    bool safeRead(const std::shared_mutex& mutex, const T& data, std::function<void(const T&)> reader);
    
    template<typename T>
    bool safeWrite(std::shared_mutex& mutex, T& data, std::function<void(T&)> writer);
    
    // Queue management utilities
    template<typename T>
    bool safeEnqueue(std::mutex& mutex, std::queue<T>& queue, const T& item, std::condition_variable& not_full_cv);
    
    template<typename T>
    bool safeDequeue(std::mutex& mutex, std::queue<T>& queue, T& item, std::condition_variable& not_empty_cv);
    
    // Cache management utilities
    template<typename K, typename V>
    bool safeCacheGet(std::shared_mutex& mutex, const std::map<K, V>& cache, const K& key, V& value);
    
    template<typename K, typename V>
    bool safeCachePut(std::shared_mutex& mutex, std::map<K, V>& cache, const K& key, const V& value, size_t max_size);
    
    // Performance measurement utilities
    class PerformanceTimer {
    private:
        std::chrono::high_resolution_clock::time_point start_time;
        std::string operation_name;
        
    public:
        PerformanceTimer(const std::string& name);
        ~PerformanceTimer();
        double getElapsedTimeMs() const;
        void reset();
    };
    
    // Thread affinity utilities
    bool setThreadAffinity(std::thread& thread, int cpu_core);
    bool setThreadPriority(std::thread& thread, int priority);
    std::vector<int> getAvailableCPUCores();
    int getOptimalCPUCore(const std::string& thread_name);
    
    // Memory management utilities
    size_t getThreadMemoryUsage();
    size_t getProcessMemoryUsage();
    void optimizeMemoryUsage();
    bool isMemoryPressureHigh();
    
    // Error handling utilities
    void setThreadErrorHandler(std::function<void(const std::string&)> handler);
    void logThreadError(const std::string& thread_name, const std::string& error);
    std::string getLastThreadError();
}

#endif // FGCOM_THREADING_INTERFACE_H



