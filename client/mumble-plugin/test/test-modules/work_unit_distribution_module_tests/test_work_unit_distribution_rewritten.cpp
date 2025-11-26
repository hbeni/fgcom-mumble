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
#include <condition_variable>
#include <random>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <queue>
#include <set>
#include <unordered_map>
#include <functional>
#include "work_unit_distributor_testable.h"

// Mock classes for testing with the new architecture
class MockWorkUnitManager {
public:
    MockWorkUnitManager() = default;
    virtual ~MockWorkUnitManager() = default;
    
    virtual std::string createWorkUnit(WorkUnitType type, const std::vector<double>& input_data, 
                                      const std::map<std::string, double>& parameters) {
        std::string unit_id = "unit_" + std::to_string(work_units.size() + 1);
        
        WorkUnit unit;
        unit.unit_id = unit_id;
        unit.type = type;
        unit.priority = WorkUnitPriority::MEDIUM;
        unit.status = WorkUnitStatus::PENDING;
        unit.input_data = input_data;
        unit.parameters = parameters;
        unit.data_size_bytes = input_data.size() * sizeof(double);
        unit.max_processing_time_ms = 5000;
        unit.created_time = std::chrono::system_clock::now();
        unit.memory_requirement_mb = 100;
        unit.requires_gpu = false;
        unit.requires_double_precision = false;
        unit.retry_count = 0;
        unit.max_retries = 3;
        unit.success = false;
        
        work_units[unit_id] = unit;
        return unit_id;
    }
    
    virtual bool assignWorkUnit(const std::string& unit_id, const std::string& client_id) {
        auto it = work_units.find(unit_id);
        if (it == work_units.end()) {
            return false;
        }
        it->second.assigned_client_id = client_id;
        it->second.status = WorkUnitStatus::ASSIGNED;
        it->second.assigned_time = std::chrono::system_clock::now();
        return true;
    }
    
    virtual bool completeWorkUnit(const std::string& unit_id, const std::vector<double>& result_data) {
        auto it = work_units.find(unit_id);
        if (it == work_units.end()) {
            return false;
        }
        it->second.result_data = result_data;
        it->second.status = WorkUnitStatus::COMPLETED;
        it->second.completed_time = std::chrono::system_clock::now();
        it->second.success = true;
        return true;
    }
    
    virtual bool failWorkUnit(const std::string& unit_id, const std::string& error_message) {
        auto it = work_units.find(unit_id);
        if (it == work_units.end()) {
            return false;
        }
        it->second.error_message = error_message;
        it->second.status = WorkUnitStatus::FAILED;
        it->second.success = false;
        return true;
    }
    
    virtual bool cancelWorkUnit(const std::string& unit_id) {
        auto it = work_units.find(unit_id);
        if (it == work_units.end()) {
            return false;
        }
        it->second.status = WorkUnitStatus::FAILED;
        return true;
    }
    
    virtual WorkUnitStatus getWorkUnitStatus(const std::string& unit_id) {
        auto it = work_units.find(unit_id);
        if (it == work_units.end()) {
            return WorkUnitStatus::FAILED;
        }
        return it->second.status;
    }
    
    virtual WorkUnit getWorkUnit(const std::string& unit_id) {
        auto it = work_units.find(unit_id);
        if (it == work_units.end()) {
            return WorkUnit();
        }
        return it->second;
    }
    
    virtual std::vector<std::string> getPendingWorkUnits() {
        std::vector<std::string> pending;
        for (const auto& pair : work_units) {
            if (pair.second.status == WorkUnitStatus::PENDING) {
                pending.push_back(pair.first);
            }
        }
        return pending;
    }
    
    virtual size_t getWorkUnitCount() {
        return work_units.size();
    }

private:
    std::map<std::string, WorkUnit> work_units;
    std::mutex work_units_mutex;
};

class MockQueueManager {
public:
    MockQueueManager() = default;
    virtual ~MockQueueManager() = default;
    
    virtual bool enqueueWorkUnit(const std::string& unit_id, WorkUnitPriority priority) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        work_unit_queue.push({unit_id, priority});
        return true;
    }
    
    virtual bool dequeueWorkUnit(std::string& unit_id, WorkUnitPriority& priority) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        if (work_unit_queue.empty()) {
            return false;
        }
        auto work_unit = work_unit_queue.top();
        work_unit_queue.pop();
        unit_id = work_unit.unit_id;
        priority = work_unit.priority;
        return true;
    }
    
    virtual bool isEmpty() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        return work_unit_queue.empty();
    }
    
    virtual size_t getQueueSize() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        return work_unit_queue.size();
    }
    
    virtual void clearQueue() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        while (!work_unit_queue.empty()) {
            work_unit_queue.pop();
        }
    }

private:
    struct WorkUnitQueueItem {
        std::string unit_id;
        WorkUnitPriority priority;
        
        bool operator>(const WorkUnitQueueItem& other) const {
            return static_cast<int>(priority) > static_cast<int>(other.priority);
        }
    };
    
    std::priority_queue<WorkUnitQueueItem, std::vector<WorkUnitQueueItem>, std::greater<WorkUnitQueueItem>> work_unit_queue;
    std::mutex queue_mutex;
};

class MockStatisticsCollector {
public:
    MockStatisticsCollector() = default;
    virtual ~MockStatisticsCollector() = default;
    
    virtual void recordWorkUnitCreated(const std::string& unit_id, WorkUnitType type) {
        (void)unit_id; (void)type; // Suppress unused parameter warnings
        stats_manager.recordWorkUnitCreated();
    }
    
    virtual void recordWorkUnitCompleted(const std::string& unit_id, bool success, 
                                       std::chrono::milliseconds processing_time) {
        (void)unit_id; (void)success; // Suppress unused parameter warnings
        stats_manager.recordWorkUnitCompleted();
        stats_manager.updateProcessingTime(static_cast<double>(processing_time.count()));
    }
    
    virtual void recordWorkUnitFailed(const std::string& unit_id, const std::string& error_message) {
        (void)unit_id; (void)error_message; // Suppress unused parameter warnings
        stats_manager.recordWorkUnitFailed();
    }
    
    virtual void recordWorkUnitTimeout(const std::string& unit_id) {
        (void)unit_id; // Suppress unused parameter warnings
        stats_manager.recordWorkUnitTimeout();
    }
    
    virtual void recordWorkUnitAssigned(const std::string& unit_id, const std::string& client_id) {
        (void)unit_id; (void)client_id; // Suppress unused parameter warnings
        stats_manager.updatePendingCount(-1);
        stats_manager.updateProcessingCount(1);
    }
    
    virtual WorkUnitDistributionStats getStatistics() {
        return stats_manager.getStatistics();
    }
    
    virtual void resetStatistics() {
        stats_manager.resetStatistics();
    }

private:
    ThreadSafeStatisticsManager stats_manager;
};

class MockClientManager {
public:
    MockClientManager() = default;
    virtual ~MockClientManager() = default;
    
    virtual bool registerClient(const std::string& client_id, const ClientWorkUnitCapability& capability) {
        return client_manager.registerClient(client_id, capability);
    }
    
    virtual bool unregisterClient(const std::string& client_id) {
        return client_manager.unregisterClient(client_id);
    }
    
    virtual bool updateClientCapability(const std::string& client_id, const ClientWorkUnitCapability& capability) {
        return client_manager.updateClientCapability(client_id, capability);
    }
    
    virtual std::vector<std::string> getAvailableClients() {
        return client_manager.getAvailableClients();
    }
    
    virtual ClientWorkUnitCapability getClientCapability(const std::string& client_id) {
        return client_manager.getClientCapability(client_id);
    }
    
    virtual size_t getClientCount() {
        return client_manager.getClientCount();
    }

private:
    ThreadSafeClientManager client_manager;
};

class MockWorkUnitResultAggregator {
public:
    MockWorkUnitResultAggregator() = default;
    virtual ~MockWorkUnitResultAggregator() = default;
    
    virtual bool addResult(const std::string& unit_id, const std::vector<double>& result_data) {
        std::lock_guard<std::mutex> lock(results_mutex);
        results[unit_id] = result_data;
        return true;
    }
    
    virtual std::vector<double> getResult(const std::string& unit_id) {
        std::lock_guard<std::mutex> lock(results_mutex);
        auto it = results.find(unit_id);
        if (it == results.end()) {
            return std::vector<double>();
        }
        return it->second;
    }
    
    virtual bool hasResult(const std::string& unit_id) {
        std::lock_guard<std::mutex> lock(results_mutex);
        return results.find(unit_id) != results.end();
    }
    
    virtual void removeResult(const std::string& unit_id) {
        std::lock_guard<std::mutex> lock(results_mutex);
        results.erase(unit_id);
    }
    
    virtual void cleanupOldResults(std::chrono::system_clock::time_point cutoff_time) {
        (void)cutoff_time; // Suppress unused parameter warnings
        std::lock_guard<std::mutex> lock(results_mutex);
        // Mock cleanup - in real implementation would remove old results
    }
    
    virtual size_t getResultCount() {
        std::lock_guard<std::mutex> lock(results_mutex);
        return results.size();
    }

private:
    std::map<std::string, std::vector<double>> results;
    std::mutex results_mutex;
};

// Test fixture for work unit distribution module
class WorkUnitDistributionModuleTest : public ::testing::Test {
protected:
    void SetUp() override {
        mock_work_unit_manager = std::make_unique<MockWorkUnitManager>();
        mock_queue_manager = std::make_unique<MockQueueManager>();
        mock_statistics_collector = std::make_unique<MockStatisticsCollector>();
        mock_client_manager = std::make_unique<MockClientManager>();
        mock_result_aggregator = std::make_unique<MockWorkUnitResultAggregator>();
    }
    
    void TearDown() override {
        mock_work_unit_manager.reset();
        mock_queue_manager.reset();
        mock_statistics_collector.reset();
        mock_client_manager.reset();
        mock_result_aggregator.reset();
    }
    
    std::unique_ptr<MockWorkUnitManager> mock_work_unit_manager;
    std::unique_ptr<MockQueueManager> mock_queue_manager;
    std::unique_ptr<MockStatisticsCollector> mock_statistics_collector;
    std::unique_ptr<MockClientManager> mock_client_manager;
    std::unique_ptr<MockWorkUnitResultAggregator> mock_result_aggregator;
};

// Test cases for work unit distribution module
TEST_F(WorkUnitDistributionModuleTest, WorkUnitCreation) {
    // Test work unit creation
    std::vector<double> input_data = {1.0, 2.0, 3.0, 4.0, 5.0};
    std::map<std::string, double> parameters = {{"frequency", 144.0}, {"power", 100.0}};
    
    std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
    EXPECT_FALSE(unit_id.empty()) << "Work unit ID should not be empty";
    
    // Test work unit retrieval
    WorkUnit unit = mock_work_unit_manager->getWorkUnit(unit_id);
    EXPECT_EQ(unit.unit_id, unit_id) << "Work unit ID should match";
    EXPECT_EQ(unit.type, WorkUnitType::PROPAGATION_GRID) << "Work unit type should match";
    EXPECT_EQ(unit.status, WorkUnitStatus::PENDING) << "Work unit should be pending";
    EXPECT_EQ(unit.input_data.size(), input_data.size()) << "Input data size should match";
    EXPECT_EQ(unit.parameters.size(), parameters.size()) << "Parameters size should match";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitAssignment) {
    // Create a work unit
    std::vector<double> input_data = {1.0, 2.0, 3.0};
    std::map<std::string, double> parameters = {{"frequency", 144.0}};
    std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
    
    // Test work unit assignment
    std::string client_id = "client_001";
    bool assignment_result = mock_work_unit_manager->assignWorkUnit(unit_id, client_id);
    EXPECT_TRUE(assignment_result) << "Work unit assignment should succeed";
    
    // Test work unit status
    WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
    EXPECT_EQ(status, WorkUnitStatus::ASSIGNED) << "Work unit should be assigned";
    
    // Test work unit retrieval
    WorkUnit unit = mock_work_unit_manager->getWorkUnit(unit_id);
    EXPECT_EQ(unit.assigned_client_id, client_id) << "Assigned client ID should match";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitCompletion) {
    // Create and assign a work unit
    std::vector<double> input_data = {1.0, 2.0, 3.0};
    std::map<std::string, double> parameters = {{"frequency", 144.0}};
    std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
    mock_work_unit_manager->assignWorkUnit(unit_id, "client_001");
    
    // Test work unit completion
    std::vector<double> result_data = {10.0, 20.0, 30.0};
    bool completion_result = mock_work_unit_manager->completeWorkUnit(unit_id, result_data);
    EXPECT_TRUE(completion_result) << "Work unit completion should succeed";
    
    // Test work unit status
    WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
    EXPECT_EQ(status, WorkUnitStatus::COMPLETED) << "Work unit should be completed";
    
    // Test work unit retrieval
    WorkUnit unit = mock_work_unit_manager->getWorkUnit(unit_id);
    EXPECT_EQ(unit.result_data.size(), result_data.size()) << "Result data size should match";
    EXPECT_TRUE(unit.success) << "Work unit should be marked as successful";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitFailure) {
    // Create and assign a work unit
    std::vector<double> input_data = {1.0, 2.0, 3.0};
    std::map<std::string, double> parameters = {{"frequency", 144.0}};
    std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
    mock_work_unit_manager->assignWorkUnit(unit_id, "client_001");
    
    // Test work unit failure
    std::string error_message = "Processing failed";
    bool failure_result = mock_work_unit_manager->failWorkUnit(unit_id, error_message);
    EXPECT_TRUE(failure_result) << "Work unit failure should succeed";
    
    // Test work unit status
    WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
    EXPECT_EQ(status, WorkUnitStatus::FAILED) << "Work unit should be failed";
    
    // Test work unit retrieval
    WorkUnit unit = mock_work_unit_manager->getWorkUnit(unit_id);
    EXPECT_EQ(unit.error_message, error_message) << "Error message should match";
    EXPECT_FALSE(unit.success) << "Work unit should be marked as failed";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitCancellation) {
    // Create a work unit
    std::vector<double> input_data = {1.0, 2.0, 3.0};
    std::map<std::string, double> parameters = {{"frequency", 144.0}};
    std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
    
    // Test work unit cancellation
    bool cancellation_result = mock_work_unit_manager->cancelWorkUnit(unit_id);
    EXPECT_TRUE(cancellation_result) << "Work unit cancellation should succeed";
    
    // Test work unit status
    WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
    EXPECT_EQ(status, WorkUnitStatus::FAILED) << "Work unit should be failed after cancellation";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitQueueOperations) {
    // Test work unit queue operations
    std::string unit_id_1 = "unit_001";
    std::string unit_id_2 = "unit_002";
    std::string unit_id_3 = "unit_003";
    
    // Test work unit enqueue
    bool enqueue_result_1 = mock_queue_manager->enqueueWorkUnit(unit_id_1, WorkUnitPriority::HIGH);
    bool enqueue_result_2 = mock_queue_manager->enqueueWorkUnit(unit_id_2, WorkUnitPriority::MEDIUM);
    bool enqueue_result_3 = mock_queue_manager->enqueueWorkUnit(unit_id_3, WorkUnitPriority::LOW);
    
    EXPECT_TRUE(enqueue_result_1) << "Work unit enqueue should succeed";
    EXPECT_TRUE(enqueue_result_2) << "Work unit enqueue should succeed";
    EXPECT_TRUE(enqueue_result_3) << "Work unit enqueue should succeed";
    
    // Test work unit queue size
    size_t queue_size = mock_queue_manager->getQueueSize();
    EXPECT_EQ(queue_size, 3) << "Work unit queue size should be 3";
    
    // Test work unit dequeue (should get highest priority first)
    std::string dequeued_unit_id;
    WorkUnitPriority dequeued_priority;
    bool dequeue_result = mock_queue_manager->dequeueWorkUnit(dequeued_unit_id, dequeued_priority);
    EXPECT_TRUE(dequeue_result) << "Work unit dequeue should succeed";
    EXPECT_EQ(dequeued_unit_id, unit_id_1) << "Highest priority work unit should be dequeued first";
    EXPECT_EQ(dequeued_priority, WorkUnitPriority::HIGH) << "Priority should match";
    
    // Test work unit queue size after dequeue
    queue_size = mock_queue_manager->getQueueSize();
    EXPECT_EQ(queue_size, 2) << "Work unit queue size should be 2 after dequeue";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitQueuePriority) {
    // Test work unit queue priority ordering
    std::string unit_id_1 = "unit_001";
    std::string unit_id_2 = "unit_002";
    std::string unit_id_3 = "unit_003";
    
    // Enqueue work units with different priorities
    mock_queue_manager->enqueueWorkUnit(unit_id_1, WorkUnitPriority::LOW);
    mock_queue_manager->enqueueWorkUnit(unit_id_2, WorkUnitPriority::HIGH);
    mock_queue_manager->enqueueWorkUnit(unit_id_3, WorkUnitPriority::MEDIUM);
    
    // Test dequeue order (should be HIGH, MEDIUM, LOW)
    std::string dequeued_unit_id;
    WorkUnitPriority dequeued_priority;
    
    // First dequeue should be HIGH priority
    bool dequeue_result = mock_queue_manager->dequeueWorkUnit(dequeued_unit_id, dequeued_priority);
    EXPECT_TRUE(dequeue_result) << "Work unit dequeue should succeed";
    EXPECT_EQ(dequeued_unit_id, unit_id_2) << "HIGH priority work unit should be dequeued first";
    EXPECT_EQ(dequeued_priority, WorkUnitPriority::HIGH) << "Priority should be HIGH";
    
    // Second dequeue should be MEDIUM priority
    dequeue_result = mock_queue_manager->dequeueWorkUnit(dequeued_unit_id, dequeued_priority);
    EXPECT_TRUE(dequeue_result) << "Work unit dequeue should succeed";
    EXPECT_EQ(dequeued_unit_id, unit_id_3) << "MEDIUM priority work unit should be dequeued second";
    EXPECT_EQ(dequeued_priority, WorkUnitPriority::MEDIUM) << "Priority should be MEDIUM";
    
    // Third dequeue should be LOW priority
    dequeue_result = mock_queue_manager->dequeueWorkUnit(dequeued_unit_id, dequeued_priority);
    EXPECT_TRUE(dequeue_result) << "Work unit dequeue should succeed";
    EXPECT_EQ(dequeued_unit_id, unit_id_1) << "LOW priority work unit should be dequeued third";
    EXPECT_EQ(dequeued_priority, WorkUnitPriority::LOW) << "Priority should be LOW";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitQueueEmpty) {
    // Test work unit queue empty state
    bool is_empty = mock_queue_manager->isEmpty();
    EXPECT_TRUE(is_empty) << "Work unit queue should be empty initially";
    
    // Test work unit enqueue
    std::string unit_id = "unit_001";
    bool enqueue_result = mock_queue_manager->enqueueWorkUnit(unit_id, WorkUnitPriority::MEDIUM);
    EXPECT_TRUE(enqueue_result) << "Work unit enqueue should succeed";
    
    // Test work unit queue not empty
    is_empty = mock_queue_manager->isEmpty();
    EXPECT_FALSE(is_empty) << "Work unit queue should not be empty after enqueue";
    
    // Test work unit dequeue
    std::string dequeued_unit_id;
    WorkUnitPriority dequeued_priority;
    bool dequeue_result = mock_queue_manager->dequeueWorkUnit(dequeued_unit_id, dequeued_priority);
    EXPECT_TRUE(dequeue_result) << "Work unit dequeue should succeed";
    EXPECT_EQ(dequeued_unit_id, unit_id) << "Dequeued work unit ID should match";
    EXPECT_EQ(dequeued_priority, WorkUnitPriority::MEDIUM) << "Dequeued priority should match";
    
    // Test work unit queue empty after dequeue
    is_empty = mock_queue_manager->isEmpty();
    EXPECT_TRUE(is_empty) << "Work unit queue should be empty after dequeue";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitQueueClear) {
    // Test work unit queue clear
    std::string unit_id_1 = "unit_001";
    std::string unit_id_2 = "unit_002";
    std::string unit_id_3 = "unit_003";
    
    // Enqueue work units
    mock_queue_manager->enqueueWorkUnit(unit_id_1, WorkUnitPriority::HIGH);
    mock_queue_manager->enqueueWorkUnit(unit_id_2, WorkUnitPriority::MEDIUM);
    mock_queue_manager->enqueueWorkUnit(unit_id_3, WorkUnitPriority::LOW);
    
    // Test work unit queue size
    size_t queue_size = mock_queue_manager->getQueueSize();
    EXPECT_EQ(queue_size, 3) << "Work unit queue size should be 3";
    
    // Test work unit queue clear
    mock_queue_manager->clearQueue();
    
    // Test work unit queue size after clear
    queue_size = mock_queue_manager->getQueueSize();
    EXPECT_EQ(queue_size, 0) << "Work unit queue size should be 0 after clear";
    
    // Test work unit queue empty after clear
    bool is_empty = mock_queue_manager->isEmpty();
    EXPECT_TRUE(is_empty) << "Work unit queue should be empty after clear";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitStatistics) {
    // Test work unit statistics collection
    std::string unit_id = "unit_001";
    WorkUnitType type = WorkUnitType::PROPAGATION_GRID;
    
    // Test work unit created statistics
    mock_statistics_collector->recordWorkUnitCreated(unit_id, type);
    WorkUnitDistributionStats stats = mock_statistics_collector->getStatistics();
    EXPECT_EQ(stats.total_units_created, 1) << "Total units created should be 1";
    
    // Test work unit completed statistics
    mock_statistics_collector->recordWorkUnitCompleted(unit_id, true, std::chrono::milliseconds(1000));
    stats = mock_statistics_collector->getStatistics();
    EXPECT_EQ(stats.total_units_completed, 1) << "Total units completed should be 1";
    EXPECT_GT(stats.average_processing_time_ms, 0.0) << "Average processing time should be positive";
    
    // Test work unit failed statistics
    mock_statistics_collector->recordWorkUnitFailed(unit_id, "Processing failed");
    stats = mock_statistics_collector->getStatistics();
    EXPECT_EQ(stats.total_units_failed, 1) << "Total units failed should be 1";
    
    // Test work unit timeout statistics
    mock_statistics_collector->recordWorkUnitTimeout(unit_id);
    stats = mock_statistics_collector->getStatistics();
    EXPECT_EQ(stats.total_units_timeout, 1) << "Total units timeout should be 1";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitStatisticsReset) {
    // Test work unit statistics reset
    std::string unit_id = "unit_001";
    WorkUnitType type = WorkUnitType::PROPAGATION_GRID;
    
    // Record some statistics
    mock_statistics_collector->recordWorkUnitCreated(unit_id, type);
    mock_statistics_collector->recordWorkUnitCompleted(unit_id, true, std::chrono::milliseconds(1000));
    mock_statistics_collector->recordWorkUnitFailed(unit_id, "Processing failed");
    mock_statistics_collector->recordWorkUnitTimeout(unit_id);
    
    // Test statistics before reset
    WorkUnitDistributionStats stats = mock_statistics_collector->getStatistics();
    EXPECT_EQ(stats.total_units_created, 1) << "Total units created should be 1 before reset";
    EXPECT_EQ(stats.total_units_completed, 1) << "Total units completed should be 1 before reset";
    EXPECT_EQ(stats.total_units_failed, 1) << "Total units failed should be 1 before reset";
    EXPECT_EQ(stats.total_units_timeout, 1) << "Total units timeout should be 1 before reset";
    
    // Test statistics reset
    mock_statistics_collector->resetStatistics();
    
    // Test statistics after reset
    stats = mock_statistics_collector->getStatistics();
    EXPECT_EQ(stats.total_units_created, 0) << "Total units created should be 0 after reset";
    EXPECT_EQ(stats.total_units_completed, 0) << "Total units completed should be 0 after reset";
    EXPECT_EQ(stats.total_units_failed, 0) << "Total units failed should be 0 after reset";
    EXPECT_EQ(stats.total_units_timeout, 0) << "Total units timeout should be 0 after reset";
}

TEST_F(WorkUnitDistributionModuleTest, ClientRegistration) {
    // Test client registration
    std::string client_id = "client_001";
    ClientWorkUnitCapability capability;
    capability.client_id = client_id;
    capability.supported_types = {WorkUnitType::PROPAGATION_GRID, WorkUnitType::ANTENNA_PATTERN};
    capability.max_concurrent_units[WorkUnitType::PROPAGATION_GRID] = 5;
    capability.max_concurrent_units[WorkUnitType::ANTENNA_PATTERN] = 3;
    capability.processing_speed_multiplier[WorkUnitType::PROPAGATION_GRID] = 1.0;
    capability.processing_speed_multiplier[WorkUnitType::ANTENNA_PATTERN] = 1.5;
    capability.max_memory_mb = 1024;
    capability.supports_gpu = true;
    capability.supports_double_precision = true;
    capability.network_bandwidth_mbps = 100.0f;
    capability.processing_latency_ms = 10.0f;
    capability.is_online = true;
    capability.last_heartbeat = std::chrono::system_clock::now();
    
    bool registration_result = mock_client_manager->registerClient(client_id, capability);
    EXPECT_TRUE(registration_result) << "Client registration should succeed";
    
    // Test client count
    size_t client_count = mock_client_manager->getClientCount();
    EXPECT_EQ(client_count, 1) << "Client count should be 1";
    
    // Test client capability retrieval
    ClientWorkUnitCapability retrieved_capability = mock_client_manager->getClientCapability(client_id);
    EXPECT_EQ(retrieved_capability.client_id, client_id) << "Client ID should match";
    EXPECT_EQ(retrieved_capability.supported_types.size(), 2) << "Supported types size should be 2";
    EXPECT_EQ(retrieved_capability.max_memory_mb, 1024) << "Max memory should match";
    EXPECT_TRUE(retrieved_capability.supports_gpu) << "GPU support should be true";
    EXPECT_TRUE(retrieved_capability.supports_double_precision) << "Double precision support should be true";
    EXPECT_TRUE(retrieved_capability.is_online) << "Online status should be true";
}

TEST_F(WorkUnitDistributionModuleTest, ClientUnregistration) {
    // Test client unregistration
    std::string client_id = "client_001";
    ClientWorkUnitCapability capability;
    capability.client_id = client_id;
    capability.is_online = true;
    
    // Register client
    bool registration_result = mock_client_manager->registerClient(client_id, capability);
    EXPECT_TRUE(registration_result) << "Client registration should succeed";
    
    // Test client count before unregistration
    size_t client_count = mock_client_manager->getClientCount();
    EXPECT_EQ(client_count, 1) << "Client count should be 1 before unregistration";
    
    // Test client unregistration
    bool unregistration_result = mock_client_manager->unregisterClient(client_id);
    EXPECT_TRUE(unregistration_result) << "Client unregistration should succeed";
    
    // Test client count after unregistration
    client_count = mock_client_manager->getClientCount();
    EXPECT_EQ(client_count, 0) << "Client count should be 0 after unregistration";
}

TEST_F(WorkUnitDistributionModuleTest, ClientCapabilityUpdate) {
    // Test client capability update
    std::string client_id = "client_001";
    ClientWorkUnitCapability capability;
    capability.client_id = client_id;
    capability.supported_types = {WorkUnitType::PROPAGATION_GRID};
    capability.max_memory_mb = 512;
    capability.supports_gpu = false;
    capability.is_online = true;
    
    // Register client
    bool registration_result = mock_client_manager->registerClient(client_id, capability);
    EXPECT_TRUE(registration_result) << "Client registration should succeed";
    
    // Test client capability update
    capability.supported_types = {WorkUnitType::PROPAGATION_GRID, WorkUnitType::ANTENNA_PATTERN};
    capability.max_memory_mb = 1024;
    capability.supports_gpu = true;
    
    bool update_result = mock_client_manager->updateClientCapability(client_id, capability);
    EXPECT_TRUE(update_result) << "Client capability update should succeed";
    
    // Test updated client capability
    ClientWorkUnitCapability updated_capability = mock_client_manager->getClientCapability(client_id);
    EXPECT_EQ(updated_capability.supported_types.size(), 2) << "Supported types size should be 2 after update";
    EXPECT_EQ(updated_capability.max_memory_mb, 1024) << "Max memory should be 1024 after update";
    EXPECT_TRUE(updated_capability.supports_gpu) << "GPU support should be true after update";
}

TEST_F(WorkUnitDistributionModuleTest, ClientAvailability) {
    // Test client availability
    std::string client_id_1 = "client_001";
    std::string client_id_2 = "client_002";
    std::string client_id_3 = "client_003";
    
    ClientWorkUnitCapability capability_1;
    capability_1.client_id = client_id_1;
    capability_1.is_online = true;
    
    ClientWorkUnitCapability capability_2;
    capability_2.client_id = client_id_2;
    capability_2.is_online = false;
    
    ClientWorkUnitCapability capability_3;
    capability_3.client_id = client_id_3;
    capability_3.is_online = true;
    
    // Register clients
    mock_client_manager->registerClient(client_id_1, capability_1);
    mock_client_manager->registerClient(client_id_2, capability_2);
    mock_client_manager->registerClient(client_id_3, capability_3);
    
    // Test available clients
    std::vector<std::string> available_clients = mock_client_manager->getAvailableClients();
    EXPECT_EQ(available_clients.size(), 2) << "Available clients count should be 2";
    
    // Test available clients contain online clients
    bool contains_client_1 = std::find(available_clients.begin(), available_clients.end(), client_id_1) != available_clients.end();
    bool contains_client_3 = std::find(available_clients.begin(), available_clients.end(), client_id_3) != available_clients.end();
    bool contains_client_2 = std::find(available_clients.begin(), available_clients.end(), client_id_2) != available_clients.end();
    
    EXPECT_TRUE(contains_client_1) << "Available clients should contain client_1";
    EXPECT_TRUE(contains_client_3) << "Available clients should contain client_3";
    EXPECT_FALSE(contains_client_2) << "Available clients should not contain client_2";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitResultAggregation) {
    // Test work unit result aggregation
    std::string unit_id = "unit_001";
    std::vector<double> result_data = {10.0, 20.0, 30.0, 40.0, 50.0};
    
    // Test result addition
    bool add_result = mock_result_aggregator->addResult(unit_id, result_data);
    EXPECT_TRUE(add_result) << "Result addition should succeed";
    
    // Test result retrieval
    std::vector<double> retrieved_result = mock_result_aggregator->getResult(unit_id);
    EXPECT_EQ(retrieved_result.size(), result_data.size()) << "Retrieved result size should match";
    EXPECT_EQ(retrieved_result[0], result_data[0]) << "Retrieved result first element should match";
    EXPECT_EQ(retrieved_result[4], result_data[4]) << "Retrieved result last element should match";
    
    // Test result existence
    bool has_result = mock_result_aggregator->hasResult(unit_id);
    EXPECT_TRUE(has_result) << "Result should exist";
    
    // Test result count
    size_t result_count = mock_result_aggregator->getResultCount();
    EXPECT_EQ(result_count, 1) << "Result count should be 1";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitResultRemoval) {
    // Test work unit result removal
    std::string unit_id = "unit_001";
    std::vector<double> result_data = {10.0, 20.0, 30.0};
    
    // Add result
    mock_result_aggregator->addResult(unit_id, result_data);
    
    // Test result existence before removal
    bool has_result = mock_result_aggregator->hasResult(unit_id);
    EXPECT_TRUE(has_result) << "Result should exist before removal";
    
    // Test result removal
    mock_result_aggregator->removeResult(unit_id);
    
    // Test result existence after removal
    has_result = mock_result_aggregator->hasResult(unit_id);
    EXPECT_FALSE(has_result) << "Result should not exist after removal";
    
    // Test result count after removal
    size_t result_count = mock_result_aggregator->getResultCount();
    EXPECT_EQ(result_count, 0) << "Result count should be 0 after removal";
}

TEST_F(WorkUnitDistributionModuleTest, WorkUnitResultCleanup) {
    // Test work unit result cleanup
    std::string unit_id_1 = "unit_001";
    std::string unit_id_2 = "unit_002";
    std::string unit_id_3 = "unit_003";
    
    std::vector<double> result_data_1 = {10.0, 20.0, 30.0};
    std::vector<double> result_data_2 = {40.0, 50.0, 60.0};
    std::vector<double> result_data_3 = {70.0, 80.0, 90.0};
    
    // Add results
    mock_result_aggregator->addResult(unit_id_1, result_data_1);
    mock_result_aggregator->addResult(unit_id_2, result_data_2);
    mock_result_aggregator->addResult(unit_id_3, result_data_3);
    
    // Test result count before cleanup
    size_t result_count = mock_result_aggregator->getResultCount();
    EXPECT_EQ(result_count, 3) << "Result count should be 3 before cleanup";
    
    // Test result cleanup
    auto cutoff_time = std::chrono::system_clock::now();
    mock_result_aggregator->cleanupOldResults(cutoff_time);
    
    // Test result count after cleanup (mock cleanup doesn't actually remove results)
    result_count = mock_result_aggregator->getResultCount();
    EXPECT_EQ(result_count, 3) << "Result count should be 3 after cleanup (mock implementation)";
}

// Main function for the test
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
