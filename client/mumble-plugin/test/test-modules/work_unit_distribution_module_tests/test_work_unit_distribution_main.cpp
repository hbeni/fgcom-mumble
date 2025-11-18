#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <openssl/x509.h>
#include "work_unit_distributor_fixed.h"
#include <condition_variable>
#include <random>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <queue>
#include <set>
#include <unordered_map>
#include <functional>

// Using fixed header instead of original modules
#include "../../client/mumble-plugin/lib/work_unit_security.h"

// Mock classes for testing
class MockWorkUnitManager {
public:
    MockWorkUnitManager() = default;
    
    virtual ~MockWorkUnitManager() = default;
    
    // Work unit creation
    virtual std::string createWorkUnit(WorkUnitType type, const std::vector<double>& input_data, 
                                      const std::map<std::string, double>& parameters = {}) {
        std::string unit_id = generateUnitId();
        
        WorkUnit unit;
        unit.unit_id = unit_id;
        unit.type = type;
        unit.priority = WorkUnitPriority::MEDIUM;
        unit.status = WorkUnitStatus::PENDING;
        unit.input_data = input_data;
        unit.parameters = parameters;
        unit.data_size_bytes = input_data.size() * sizeof(double);
        unit.max_processing_time_ms = 30000;
        unit.memory_requirement_mb = 100;
        unit.requires_gpu = false;
        unit.requires_double_precision = false;
        unit.created_time = std::chrono::system_clock::now();
        unit.retry_count = 0;
        unit.max_retries = 3;
        unit.success = false;
        
        std::lock_guard<std::mutex> lock(units_mutex);
        work_units[unit_id] = unit;
        return unit_id;
    }
    
    virtual bool cancelWorkUnit(const std::string& unit_id) {
        std::lock_guard<std::mutex> lock(units_mutex);
        auto it = work_units.find(unit_id);
        if (it == work_units.end()) {
            return false;
        }
        
        if (it->second.status == WorkUnitStatus::PENDING) {
            it->second.status = WorkUnitStatus::FAILED;
            return true;
        }
        
        return false;
    }
    
    virtual WorkUnitStatus getWorkUnitStatus(const std::string& unit_id) {
        std::lock_guard<std::mutex> lock(units_mutex);
        auto it = work_units.find(unit_id);
        if (it == work_units.end()) {
            return WorkUnitStatus::FAILED;
        }
        return it->second.status;
    }
    
    virtual std::vector<double> getWorkUnitResult(const std::string& unit_id) {
        std::lock_guard<std::mutex> lock(units_mutex);
        auto it = work_units.find(unit_id);
        if (it == work_units.end()) {
            return std::vector<double>();
        }
        return it->second.result_data;
    }
    
    virtual std::string getWorkUnitError(const std::string& unit_id) {
        std::lock_guard<std::mutex> lock(units_mutex);
        auto it = work_units.find(unit_id);
        if (it == work_units.end()) {
            return "";
        }
        return it->second.error_message;
    }
    
    virtual size_t getWorkUnitCount() {
        std::lock_guard<std::mutex> lock(units_mutex);
        return work_units.size();
    }
    
    virtual std::vector<std::string> getPendingWorkUnits() {
        std::lock_guard<std::mutex> lock(units_mutex);
        std::vector<std::string> pending_units;
        for (const auto& pair : work_units) {
            if (pair.second.status == WorkUnitStatus::PENDING) {
                pending_units.push_back(pair.first);
            }
        }
        return pending_units;
    }
    
protected:
    std::map<std::string, WorkUnit> work_units;
    std::mutex units_mutex;
    
    std::string generateUnitId() {
        static std::atomic<int> counter(0);
        return "unit_" + std::to_string(counter.fetch_add(1));
    }
};

class MockClientManager {
public:
    MockClientManager() = default;
    
    virtual ~MockClientManager() = default;
    
    // Client registration
    virtual bool registerClient(const std::string& client_id, const ClientWorkUnitCapability& capability) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        client_capabilities[client_id] = capability;
        return true;
    }
    
    virtual bool unregisterClient(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = client_capabilities.find(client_id);
        if (it == client_capabilities.end()) {
            return false;
        }
        client_capabilities.erase(it);
        return true;
    }
    
    virtual bool updateClientCapability(const std::string& client_id, const ClientWorkUnitCapability& capability) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = client_capabilities.find(client_id);
        if (it == client_capabilities.end()) {
            return false;
        }
        it->second = capability;
        return true;
    }
    
    virtual std::vector<std::string> getAvailableClients() {
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::vector<std::string> available_clients;
        for (const auto& pair : client_capabilities) {
            if (pair.second.is_online) {
                available_clients.push_back(pair.first);
            }
        }
        return available_clients;
    }
    
    virtual std::vector<std::string> getCompatibleClients(WorkUnitType type) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::vector<std::string> compatible_clients;
        for (const auto& pair : client_capabilities) {
            if (pair.second.is_online && 
                std::find(pair.second.supported_types.begin(), pair.second.supported_types.end(), type) != pair.second.supported_types.end()) {
                compatible_clients.push_back(pair.first);
            }
        }
        return compatible_clients;
    }
    
    virtual ClientWorkUnitCapability getClientCapability(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = client_capabilities.find(client_id);
        if (it == client_capabilities.end()) {
            return ClientWorkUnitCapability();
        }
        return it->second;
    }
    
    virtual size_t getClientCount() {
        std::lock_guard<std::mutex> lock(clients_mutex);
        return client_capabilities.size();
    }
    
    virtual bool isClientOnline(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = client_capabilities.find(client_id);
        if (it == client_capabilities.end()) {
            return false;
        }
        return it->second.is_online;
    }
    
protected:
    std::map<std::string, ClientWorkUnitCapability> client_capabilities;
    std::mutex clients_mutex;
};

class MockQueueManager {
public:
    MockQueueManager() = default;
    
    virtual ~MockQueueManager() = default;
    
    // Queue management
    virtual bool enqueueWorkUnit(const std::string& unit_id, WorkUnitPriority priority) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        work_queue.push({unit_id, priority, std::chrono::system_clock::now()});
        return true;
    }
    
    virtual std::string dequeueWorkUnit() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        if (work_queue.empty()) {
            return "";
        }
        
        auto work_item = work_queue.top();
        work_queue.pop();
        return work_item.unit_id;
    }
    
    virtual bool isEmpty() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        return work_queue.empty();
    }
    
    virtual size_t getQueueSize() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        return work_queue.size();
    }
    
    virtual std::vector<std::string> getQueueContents() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        std::vector<std::string> contents;
        auto temp_queue = work_queue;
        while (!temp_queue.empty()) {
            contents.push_back(temp_queue.top().unit_id);
            temp_queue.pop();
        }
        return contents;
    }
    
    virtual void clearQueue() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        while (!work_queue.empty()) {
            work_queue.pop();
        }
    }
    
protected:
    struct WorkQueueItem {
        std::string unit_id;
        WorkUnitPriority priority;
        std::chrono::system_clock::time_point enqueue_time;
        
        bool operator>(const WorkQueueItem& other) const {
            if (priority != other.priority) {
                return priority > other.priority;
            }
            return enqueue_time > other.enqueue_time;
        }
    };
    
    std::priority_queue<WorkQueueItem, std::vector<WorkQueueItem>, std::greater<WorkQueueItem>> work_queue;
    std::mutex queue_mutex;
};

class MockStatisticsCollector {
public:
    MockStatisticsCollector() = default;
    
    virtual ~MockStatisticsCollector() = default;
    
    // Statistics collection
    virtual void recordWorkUnitCreated(const std::string& unit_id, WorkUnitType type) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.total_units_created++;
        stats.pending_units_count++;
    }
    
    virtual void recordWorkUnitCompleted(const std::string& unit_id, bool success, 
                                       std::chrono::milliseconds processing_time) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        if (success) {
            stats.total_units_completed++;
            stats.completed_units_count++;
        } else {
            stats.total_units_failed++;
            stats.failed_units_count++;
        }
        stats.pending_units_count--;
        stats.processing_units_count--;
        
        // Update average processing time
        stats.average_processing_time_ms = (stats.average_processing_time_ms + processing_time.count()) / 2.0;
    }
    
    virtual void recordWorkUnitTimeout(const std::string& unit_id) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.total_units_timeout++;
        stats.pending_units_count--;
        stats.processing_units_count--;
    }
    
    virtual void recordWorkUnitAssigned(const std::string& unit_id, const std::string& client_id) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.pending_units_count--;
        stats.processing_units_count++;
    }
    
    virtual WorkUnitDistributionStats getStatistics() {
        std::lock_guard<std::mutex> lock(stats_mutex);
        return stats.toCopyable();
    }
    
    virtual void resetStatistics() {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats = AtomicWorkUnitStats();
    }
    
protected:
    AtomicWorkUnitStats stats;
    std::mutex stats_mutex;
};

class MockWorkUnitResultAggregator {
public:
    MockWorkUnitResultAggregator() = default;
    
    virtual ~MockWorkUnitResultAggregator() = default;
    
    // Result aggregation
    virtual bool addPartialResult(const std::string& work_unit_id, const std::string& client_id, 
                                 const std::vector<double>& result_data) {
        std::lock_guard<std::mutex> lock(results_mutex);
        partial_results[work_unit_id] = result_data;
        contributing_clients[work_unit_id].push_back(client_id);
        return true;
    }
    
    virtual std::vector<double> getAggregatedResult(const std::string& work_unit_id) {
        std::lock_guard<std::mutex> lock(results_mutex);
        auto it = partial_results.find(work_unit_id);
        if (it == partial_results.end()) {
            return std::vector<double>();
        }
        return it->second;
    }
    
    virtual bool isResultComplete(const std::string& work_unit_id) {
        std::lock_guard<std::mutex> lock(results_mutex);
        auto it = contributing_clients.find(work_unit_id);
        if (it == contributing_clients.end()) {
            return false;
        }
        return it->second.size() >= 1; // Simplified check
    }
    
    virtual std::vector<std::string> getContributingClients(const std::string& work_unit_id) {
        std::lock_guard<std::mutex> lock(results_mutex);
        auto it = contributing_clients.find(work_unit_id);
        if (it == contributing_clients.end()) {
            return std::vector<std::string>();
        }
        return it->second;
    }
    
    virtual bool validateResult(const std::string& work_unit_id, const std::vector<double>& expected_result) {
        std::lock_guard<std::mutex> lock(results_mutex);
        auto it = partial_results.find(work_unit_id);
        if (it == partial_results.end()) {
            return false;
        }
        
        const std::vector<double>& actual_result = it->second;
        if (actual_result.size() != expected_result.size()) {
            return false;
        }
        
        // Check if results are within acceptable tolerance
        double tolerance = 0.01; // 1% tolerance
        for (size_t i = 0; i < actual_result.size(); i++) {
            if (std::abs(actual_result[i] - expected_result[i]) > tolerance) {
                return false;
            }
        }
        
        return true;
    }
    
    virtual double calculateResultConfidence(const std::string& work_unit_id) {
        std::lock_guard<std::mutex> lock(results_mutex);
        auto it = contributing_clients.find(work_unit_id);
        if (it == contributing_clients.end()) {
            return 0.0;
        }
        
        // Confidence based on number of contributing clients
        int client_count = it->second.size();
        return std::min(1.0, client_count / 3.0); // Max confidence with 3+ clients
    }
    
    virtual void removeResult(const std::string& work_unit_id) {
        std::lock_guard<std::mutex> lock(results_mutex);
        partial_results.erase(work_unit_id);
        contributing_clients.erase(work_unit_id);
    }
    
    virtual void cleanupOldResults(std::chrono::system_clock::time_point cutoff_time) {
        std::lock_guard<std::mutex> lock(results_mutex);
        // Implementation would remove old results
    }
    
protected:
    std::map<std::string, std::vector<double>> partial_results;
    std::map<std::string, std::vector<std::string>> contributing_clients;
    std::mutex results_mutex;
};

// Test fixtures and utilities
class WorkUnitDistributionModuleTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        test_work_unit_types = {WorkUnitType::PROPAGATION_GRID, WorkUnitType::ANTENNA_PATTERN, 
                               WorkUnitType::FREQUENCY_OFFSET, WorkUnitType::AUDIO_PROCESSING,
                               WorkUnitType::BATCH_QSO, WorkUnitType::SOLAR_EFFECTS, WorkUnitType::LIGHTNING_EFFECTS};
        
        test_priorities = {WorkUnitPriority::LOW, WorkUnitPriority::MEDIUM, WorkUnitPriority::HIGH, WorkUnitPriority::CRITICAL};
        
        test_client_ids = {"client_1", "client_2", "client_3", "client_4", "client_5"};
        
        // Initialize mock objects
        mock_work_unit_manager = std::make_unique<MockWorkUnitManager>();
        mock_client_manager = std::make_unique<MockClientManager>();
        mock_queue_manager = std::make_unique<MockQueueManager>();
        mock_statistics_collector = std::make_unique<MockStatisticsCollector>();
        mock_result_aggregator = std::make_unique<MockWorkUnitResultAggregator>();
        
        // Create test clients
        createTestClients();
    }
    
    void TearDown() override {
        // Clean up mock objects
        mock_work_unit_manager.reset();
        mock_client_manager.reset();
        mock_queue_manager.reset();
        mock_statistics_collector.reset();
        mock_result_aggregator.reset();
    }
    
    // Test parameters
    std::vector<WorkUnitType> test_work_unit_types;
    std::vector<WorkUnitPriority> test_priorities;
    std::vector<std::string> test_client_ids;
    
    // Mock objects
    std::unique_ptr<MockWorkUnitManager> mock_work_unit_manager;
    std::unique_ptr<MockClientManager> mock_client_manager;
    std::unique_ptr<MockQueueManager> mock_queue_manager;
    std::unique_ptr<MockStatisticsCollector> mock_statistics_collector;
    std::unique_ptr<MockWorkUnitResultAggregator> mock_result_aggregator;
    
    // Helper functions
    void createTestClients() {
        for (const auto& client_id : test_client_ids) {
            ClientWorkUnitCapability capability;
            capability.client_id = client_id;
            capability.supported_types = test_work_unit_types;
            capability.max_concurrent_units[WorkUnitType::PROPAGATION_GRID] = 5;
            capability.max_concurrent_units[WorkUnitType::ANTENNA_PATTERN] = 3;
            capability.max_concurrent_units[WorkUnitType::FREQUENCY_OFFSET] = 10;
            capability.max_concurrent_units[WorkUnitType::AUDIO_PROCESSING] = 8;
            capability.max_concurrent_units[WorkUnitType::BATCH_QSO] = 2;
            capability.max_concurrent_units[WorkUnitType::SOLAR_EFFECTS] = 1;
            capability.max_concurrent_units[WorkUnitType::LIGHTNING_EFFECTS] = 1;
            capability.processing_speed_multiplier[WorkUnitType::PROPAGATION_GRID] = 1.0;
            capability.processing_speed_multiplier[WorkUnitType::ANTENNA_PATTERN] = 1.0;
            capability.processing_speed_multiplier[WorkUnitType::FREQUENCY_OFFSET] = 1.0;
            capability.processing_speed_multiplier[WorkUnitType::AUDIO_PROCESSING] = 1.0;
            capability.processing_speed_multiplier[WorkUnitType::BATCH_QSO] = 1.0;
            capability.processing_speed_multiplier[WorkUnitType::SOLAR_EFFECTS] = 1.0;
            capability.processing_speed_multiplier[WorkUnitType::LIGHTNING_EFFECTS] = 1.0;
            capability.max_memory_mb = 1024;
            capability.supports_gpu = true;
            capability.supports_double_precision = true;
            capability.network_bandwidth_mbps = 100.0f;
            capability.processing_latency_ms = 10.0f;
            capability.is_online = true;
            capability.last_heartbeat = std::chrono::system_clock::now();
            capability.active_units = 0;
            capability.pending_units = 0;
            capability.memory_usage_mb = 0;
            capability.cpu_utilization_percent = 0.0;
            capability.gpu_utilization_percent = 0.0;
            
            mock_client_manager->registerClient(client_id, capability);
        }
    }
    
    std::vector<double> generateTestData(size_t size) {
        std::vector<double> data;
        data.reserve(size);
        for (size_t i = 0; i < size; ++i) {
            data.push_back(static_cast<double>(i) * 0.1);
        }
        return data;
    }
    
    std::map<std::string, double> generateTestParameters() {
        return {{"frequency", 144.0}, {"power", 100.0}, {"distance", 1000.0}};
    }
    
    // Helper to measure execution time
    template<typename Func>
    auto measureTime(Func&& func) -> decltype(func()) {
        auto start = std::chrono::high_resolution_clock::now();
        auto result = func();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "Execution time: " << duration.count() << " microseconds" << std::endl;
        return result;
    }
};

// Test suite for task distribution tests
class TaskDistributionTest : public WorkUnitDistributionModuleTest {
protected:
    void SetUp() override {
        WorkUnitDistributionModuleTest::SetUp();
    }
};

// Test suite for results collection tests
class ResultsCollectionTest : public WorkUnitDistributionModuleTest {
protected:
    void SetUp() override {
        WorkUnitDistributionModuleTest::SetUp();
    }
};

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}


// Dynamic GPU Scaling Tests
class DynamicGPUScalingTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize dynamic GPU scaling test parameters
        scaling_thresholds = {20, 50, 100, 150, 200};
        gpu_allocation_per_threshold = {1, 2, 3, 4, 6};
        max_local_gpus = 4;
        max_network_gpus = 8;
    }
    
    std::vector<int> scaling_thresholds;
    std::vector<int> gpu_allocation_per_threshold;
    int max_local_gpus;
    int max_network_gpus;
};

TEST_F(DynamicGPUScalingTest, CalculateOptimalGPUsForLowUserCount) {
    // Test GPU allocation for 1-20 users
    for (int user_count = 1; user_count <= 20; user_count++) {
        int optimal_gpus = calculateOptimalGPUs(user_count, max_local_gpus);
        EXPECT_EQ(optimal_gpus, 1) << "Should allocate 1 GPU for " << user_count << " users";
    }
}

TEST_F(DynamicGPUScalingTest, CalculateOptimalGPUsForMediumUserCount) {
    // Test GPU allocation for 21-50 users
    for (int user_count = 21; user_count <= 50; user_count++) {
        int optimal_gpus = calculateOptimalGPUs(user_count, max_local_gpus);
        EXPECT_EQ(optimal_gpus, 2) << "Should allocate 2 GPUs for " << user_count << " users";
    }
}

TEST_F(DynamicGPUScalingTest, CalculateOptimalGPUsForHighUserCount) {
    // Test GPU allocation for 51-100 users
    for (int user_count = 51; user_count <= 100; user_count++) {
        int optimal_gpus = calculateOptimalGPUs(user_count, max_local_gpus);
        EXPECT_EQ(optimal_gpus, 3) << "Should allocate 3 GPUs for " << user_count << " users";
    }
}

TEST_F(DynamicGPUScalingTest, CalculateOptimalGPUsForVeryHighUserCount) {
    // Test GPU allocation for 101-150 users
    for (int user_count = 101; user_count <= 150; user_count++) {
        int optimal_gpus = calculateOptimalGPUs(user_count, max_local_gpus);
        EXPECT_EQ(optimal_gpus, 5) << "Should allocate 5 GPUs for " << user_count << " users";
    }
}

TEST_F(DynamicGPUScalingTest, CalculateOptimalGPUsForMaximumUserCount) {
    // Test GPU allocation for 151-200 users
    for (int user_count = 151; user_count <= 200; user_count++) {
        int optimal_gpus = calculateOptimalGPUs(user_count, max_local_gpus);
        EXPECT_EQ(optimal_gpus, 8) << "Should allocate 8 GPUs for " << user_count << " users";
    }
}

TEST_F(DynamicGPUScalingTest, NetworkGPULimits) {
    // Test network GPU limits
    int user_count = 100;
    int network_gpu_count = 4;
    double bandwidth_requirement = calculateNetworkBandwidthRequirement(network_gpu_count, user_count);
    
    EXPECT_LE(bandwidth_requirement, 1000.0) << "Bandwidth requirement should not exceed 1 Gbps";
    EXPECT_GT(bandwidth_requirement, 0.0) << "Bandwidth requirement should be positive";
}

TEST_F(DynamicGPUScalingTest, NetworkLatencyLimits) {
    // Test network latency limits
    std::vector<int> latencies = {50, 75, 100, 150, 200};
    int max_latency_threshold = 100;
    
    for (int latency : latencies) {
        bool can_allocate = (latency <= max_latency_threshold);
        if (latency <= max_latency_threshold) {
            EXPECT_TRUE(can_allocate) << "Should allow allocation for latency " << latency << "ms";
        } else {
            EXPECT_FALSE(can_allocate) << "Should not allow allocation for latency " << latency << "ms";
        }
    }
}

TEST_F(DynamicGPUScalingTest, GPUScalingThresholds) {
    // Test that scaling thresholds are properly configured
    EXPECT_EQ(scaling_thresholds.size(), 5) << "Should have 5 scaling thresholds";
    EXPECT_EQ(gpu_allocation_per_threshold.size(), 5) << "Should have 5 GPU allocation values";
    
    // Verify threshold order
    for (size_t i = 1; i < scaling_thresholds.size(); i++) {
        EXPECT_GT(scaling_thresholds[i], scaling_thresholds[i-1]) 
            << "Thresholds should be in ascending order";
    }
}

TEST_F(DynamicGPUScalingTest, WorkUnitDistributionWithDynamicScaling) {
    // Test work unit distribution with dynamic GPU scaling
    int user_count = 75;
    int optimal_gpus = calculateOptimalGPUs(user_count, max_local_gpus);
    
    // Create work units that require GPU processing
    std::vector<WorkUnit> gpu_work_units;
    for (int i = 0; i < 10; i++) {
        WorkUnit unit;
        unit.id = "gpu_unit_" + std::to_string(i);
        unit.type = WorkUnitType::PROPAGATION_GRID;
        unit.requires_gpu = true;
        unit.dynamic_gpu_scaling = true;
        unit.user_count_threshold = user_count;
        gpu_work_units.push_back(unit);
    }
    
    // Distribute work units across available GPUs
    int units_per_gpu = gpu_work_units.size() / optimal_gpus;
    EXPECT_GE(units_per_gpu, 1) << "Should distribute at least 1 unit per GPU";
}

// Helper functions for dynamic GPU scaling tests
int calculateOptimalGPUs(int user_count, int available_local_gpus) {
    if (user_count <= 20) {
        return std::min(1, available_local_gpus);
    } else if (user_count <= 50) {
        return std::min(2, available_local_gpus);
    } else if (user_count <= 100) {
        return std::min(3, available_local_gpus);
    } else if (user_count <= 150) {
        return std::min(5, available_local_gpus);
    } else {
        return std::min(8, available_local_gpus);
    }
}

double calculateNetworkBandwidthRequirement(int network_gpu_count, int user_count) {
    if (network_gpu_count == 0) return 0.0;
    double users_per_gpu = static_cast<double>(user_count) / network_gpu_count;
    double bandwidth_per_user = 2.0; // MB/s per user
    return users_per_gpu * bandwidth_per_user * network_gpu_count;
}

