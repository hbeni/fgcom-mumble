/*
 * Work Unit Distributor Implementation
 * 
 * This file implements the work unit distribution system for distributing
 * propagation calculations and other compute-intensive tasks between
 * server and clients based on their capabilities and current load.
 */

#include "work_unit_distributor.h"
#include "work_unit/work_unit_sharing.h"
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <chrono>
#include <thread>

// Static member definitions
std::unique_ptr<FGCom_WorkUnitDistributor> FGCom_WorkUnitDistributor::instance = nullptr;
std::mutex FGCom_WorkUnitDistributor::instance_mutex;

// Singleton access
FGCom_WorkUnitDistributor& FGCom_WorkUnitDistributor::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::make_unique<FGCom_WorkUnitDistributor>();
    }
    return *instance;
}

void FGCom_WorkUnitDistributor::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (instance) {
        instance->shutdown();
        instance.reset();
    }
}

// Constructor
FGCom_WorkUnitDistributor::FGCom_WorkUnitDistributor() 
    : distribution_enabled(false)
    , max_concurrent_units(10)
    , max_queue_size(1000)
    , unit_timeout_ms(30000)
    , enable_retry(true)
    , max_retries(3)
    , retry_delay_ms(1000)
    , workers_running(false)
    , sharing_manager(nullptr) {
    
    // Initialize statistics
    stats.total_units_created = 0;
    stats.total_units_completed = 0;
    stats.total_units_failed = 0;
    stats.total_units_timeout = 0;
    stats.average_processing_time_ms = 0.0;
    stats.average_queue_wait_time_ms = 0.0;
    stats.distribution_efficiency_percent = 0.0;
    stats.pending_units_count = 0;
    stats.processing_units_count = 0;
    stats.completed_units_count = 0;
    stats.failed_units_count = 0;
}

// Initialization with proper error handling and atomic operations
bool FGCom_WorkUnitDistributor::initialize() {
    // Use atomic operations to prevent race conditions
    bool expected = false;
    if (!distribution_enabled.compare_exchange_strong(expected, true)) {
        return true; // Already initialized
    }
    
    try {
        // Initialize component managers
        work_unit_manager = std::make_unique<WorkUnitManager>();
        client_manager = std::make_unique<ClientManager>();
        queue_manager = std::make_unique<QueueManager>();
        statistics_collector = std::make_unique<StatisticsCollector>();
        thread_manager = std::make_unique<ThreadManager>();
        
        // Initialize work unit sharing manager (modular sharing interface)
        sharing_manager = &FGCom_WorkUnitSharingManager::getInstance();
        if (!sharing_manager->initialize("direct")) {
            std::cerr << "[WorkUnitDistributor] Failed to initialize sharing manager" << std::endl;
            distribution_enabled = false;
            return false;
        }
        
        // Start worker threads with proper error handling
        int num_threads = std::min(4, static_cast<int>(std::thread::hardware_concurrency()));
        if (num_threads <= 0) {
            num_threads = 1; // Fallback to single thread
        }
        
        if (!thread_manager->startWorkers(num_threads)) {
            distribution_enabled = false;
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        // Proper error handling with cleanup
        distribution_enabled = false;
        std::cerr << "[WorkUnitDistributor] Initialization failed: " << e.what() << std::endl;
        return false;
    } catch (...) {
        // Handle unknown exceptions
        distribution_enabled = false;
        std::cerr << "[WorkUnitDistributor] Unknown exception during initialization" << std::endl;
        return false;
    }
}

void FGCom_WorkUnitDistributor::shutdown() {
    if (!distribution_enabled) {
        return;
    }
    
    // Stop worker threads
    workers_running = false;
    queue_condition.notify_all();
    
    for (auto& thread : worker_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads.clear();
    
    distribution_enabled = false;
}

void FGCom_WorkUnitDistributor::setConfiguration(const std::map<std::string, std::string>& config) {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto it = config.find("max_concurrent_units");
    if (it != config.end()) {
        max_concurrent_units = std::stoi(it->second);
    }
    
    it = config.find("max_queue_size");
    if (it != config.end()) {
        max_queue_size = std::stoi(it->second);
    }
    
    it = config.find("unit_timeout_ms");
    if (it != config.end()) {
        unit_timeout_ms = std::stoi(it->second);
    }
    
    it = config.find("enable_retry");
    if (it != config.end()) {
        enable_retry = (it->second == "true" || it->second == "1");
    }
    
    it = config.find("max_retries");
    if (it != config.end()) {
        max_retries = std::stoi(it->second);
    }
    
    it = config.find("retry_delay_ms");
    if (it != config.end()) {
        retry_delay_ms = std::stoi(it->second);
    }
}

// Work unit management
std::string FGCom_WorkUnitDistributor::createWorkUnit(WorkUnitType type, 
                                                     const std::vector<double>& input_data,
                                                     const std::map<std::string, double>& parameters) {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    // Generate unique unit ID
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::stringstream ss;
    ss << "unit_" << timestamp << "_" << std::hex << std::hash<std::string>{}(std::to_string(timestamp));
    std::string unit_id = ss.str();
    
    // Create work unit
    WorkUnit unit;
    unit.unit_id = unit_id;
    unit.type = type;
    unit.priority = WorkUnitPriority::MEDIUM; // Default priority
    unit.status = WorkUnitStatus::PENDING;
    unit.input_data = input_data;
    unit.parameters = parameters;
    unit.data_size_bytes = input_data.size() * sizeof(double);
    unit.max_processing_time_ms = unit_timeout_ms;
    unit.memory_requirement_mb = (input_data.size() * sizeof(double)) / (1024 * 1024);
    unit.requires_gpu = (type == WorkUnitType::ANTENNA_PATTERN || type == WorkUnitType::PROPAGATION_GRID);
    unit.requires_double_precision = true;
    unit.created_time = now;
    unit.retry_count = 0;
    unit.max_retries = max_retries;
    unit.success = false;
    
    // Add to work units map
    work_units[unit_id] = unit;
    
    // Add to pending queue
    pending_units_queue.push(unit_id);
    stats.pending_units_count++;
    stats.total_units_created++;
    
    // Notify worker threads
    queue_condition.notify_one();
    
    return unit_id;
}

bool FGCom_WorkUnitDistributor::cancelWorkUnit(const std::string& unit_id) {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto it = work_units.find(unit_id);
    if (it == work_units.end()) {
        return false;
    }
    
    WorkUnit& unit = it->second;
    if (unit.status == WorkUnitStatus::COMPLETED || unit.status == WorkUnitStatus::FAILED) {
        return false; // Cannot cancel completed/failed units
    }
    
    // Update status
    unit.status = WorkUnitStatus::FAILED;
    unit.error_message = "Cancelled by user";
    
    // Remove from client assignment if assigned
    if (!unit.assigned_client_id.empty()) {
        auto client_it = client_assigned_units.find(unit.assigned_client_id);
        if (client_it != client_assigned_units.end()) {
            auto& assigned = client_it->second;
            assigned.erase(std::remove(assigned.begin(), assigned.end(), unit_id), assigned.end());
        }
    }
    
    stats.pending_units_count--;
    stats.failed_units_count++;
    
    return true;
}

WorkUnitStatus FGCom_WorkUnitDistributor::getWorkUnitStatus(const std::string& unit_id) {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto it = work_units.find(unit_id);
    if (it == work_units.end()) {
        return WorkUnitStatus::FAILED; // Unit not found
    }
    
    return it->second.status;
}

std::vector<double> FGCom_WorkUnitDistributor::getWorkUnitResult(const std::string& unit_id) {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto it = work_units.find(unit_id);
    if (it == work_units.end() || it->second.status != WorkUnitStatus::COMPLETED) {
        return std::vector<double>(); // Empty result
    }
    
    return it->second.result_data;
}

std::string FGCom_WorkUnitDistributor::getWorkUnitError(const std::string& unit_id) {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto it = work_units.find(unit_id);
    if (it == work_units.end()) {
        return "Work unit not found";
    }
    
    return it->second.error_message;
}

// Client management
bool FGCom_WorkUnitDistributor::registerClient(const std::string& client_id, 
                                              const ClientWorkUnitCapability& capability) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    // Use operator[] to get or create entry, then update values manually
    ClientWorkUnitCapability& cap = client_capabilities[client_id];
    cap.client_id = capability.client_id;
    cap.supported_types = capability.supported_types;
    cap.max_concurrent_units = capability.max_concurrent_units;
    cap.processing_speed_multiplier = capability.processing_speed_multiplier;
    cap.max_memory_mb = capability.max_memory_mb;
    cap.supports_gpu = capability.supports_gpu;
    cap.supports_double_precision = capability.supports_double_precision;
    cap.network_bandwidth_mbps = capability.network_bandwidth_mbps;
    cap.processing_latency_ms = capability.processing_latency_ms;
    cap.is_online = capability.is_online;
    cap.last_heartbeat = capability.last_heartbeat;
    // Atomic members - update values
    cap.active_units.store(capability.active_units.load());
    cap.pending_units.store(capability.pending_units.load());
    cap.memory_usage_mb.store(capability.memory_usage_mb.load());
    cap.cpu_utilization_percent.store(capability.cpu_utilization_percent.load());
    cap.gpu_utilization_percent.store(capability.gpu_utilization_percent.load());
    client_assigned_units[client_id] = std::vector<std::string>();
    
    return true;
}

bool FGCom_WorkUnitDistributor::unregisterClient(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_capabilities.find(client_id);
    if (it == client_capabilities.end()) {
        return false;
    }
    
    // Reassign or fail all assigned units
    auto assigned_it = client_assigned_units.find(client_id);
    if (assigned_it != client_assigned_units.end()) {
        for (const std::string& unit_id : assigned_it->second) {
            // Mark units as failed or reassign them
            auto unit_it = work_units.find(unit_id);
            if (unit_it != work_units.end()) {
                unit_it->second.status = WorkUnitStatus::FAILED;
                unit_it->second.error_message = "Client disconnected";
                stats.failed_units_count++;
            }
        }
        client_assigned_units.erase(assigned_it);
    }
    
    client_capabilities.erase(it);
    return true;
}

bool FGCom_WorkUnitDistributor::updateClientCapability(const std::string& client_id, 
                                                      const ClientWorkUnitCapability& capability) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_capabilities.find(client_id);
    if (it == client_capabilities.end()) {
        return false;
    }
    
    // Update capability - copy non-atomic members manually
    it->second.client_id = capability.client_id;
    it->second.supported_types = capability.supported_types;
    it->second.max_concurrent_units = capability.max_concurrent_units;
    it->second.processing_speed_multiplier = capability.processing_speed_multiplier;
    it->second.max_memory_mb = capability.max_memory_mb;
    it->second.supports_gpu = capability.supports_gpu;
    it->second.supports_double_precision = capability.supports_double_precision;
    it->second.network_bandwidth_mbps = capability.network_bandwidth_mbps;
    it->second.processing_latency_ms = capability.processing_latency_ms;
    it->second.is_online = capability.is_online;
    it->second.last_heartbeat = capability.last_heartbeat;
    // Atomic members - update values
    it->second.active_units.store(capability.active_units.load());
    it->second.pending_units.store(capability.pending_units.load());
    it->second.memory_usage_mb.store(capability.memory_usage_mb.load());
    it->second.cpu_utilization_percent.store(capability.cpu_utilization_percent.load());
    it->second.gpu_utilization_percent.store(capability.gpu_utilization_percent.load());
    
    return true;
}

std::vector<std::string> FGCom_WorkUnitDistributor::getAvailableClients() {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    std::vector<std::string> available_clients;
    for (const auto& pair : client_capabilities) {
        if (pair.second.is_online) {
            available_clients.push_back(pair.first);
        }
    }
    
    return available_clients;
}

// Static empty capability for return when not found
static ClientWorkUnitCapability empty_capability;

const ClientWorkUnitCapability& FGCom_WorkUnitDistributor::getClientCapability(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_capabilities.find(client_id);
    if (it == client_capabilities.end()) {
        return empty_capability;
    }
    
    return it->second;
}

// Work unit distribution
bool FGCom_WorkUnitDistributor::distributeWorkUnit(const std::string& unit_id) {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto it = work_units.find(unit_id);
    if (it == work_units.end()) {
        return false;
    }
    
    WorkUnit& unit = it->second;
    if (unit.status != WorkUnitStatus::PENDING) {
        return false; // Unit not in pending state
    }
    
    // Select optimal client
    std::string optimal_client = selectOptimalClient(unit);
    if (optimal_client.empty()) {
        return false; // No suitable client available
    }
    
    // Assign work unit to client
    return assignWorkUnit(unit_id, optimal_client);
}

bool FGCom_WorkUnitDistributor::processWorkUnitResult(const std::string& unit_id, 
                                                     const std::vector<double>& result_data,
                                                     bool success, 
                                                     const std::string& error_message) {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto it = work_units.find(unit_id);
    if (it == work_units.end()) {
        return false;
    }
    
    WorkUnit& unit = it->second;
    if (unit.status != WorkUnitStatus::PROCESSING) {
        return false; // Unit not in processing state
    }
    
    // Update unit with results
    unit.result_data = result_data;
    unit.result_size_bytes = result_data.size() * sizeof(double);
    unit.success = success;
    unit.error_message = error_message;
    unit.completed_time = std::chrono::system_clock::now();
    
    if (success) {
        unit.status = WorkUnitStatus::COMPLETED;
        stats.total_units_completed++;
        stats.completed_units_count++;
        stats.processing_units_count--;
        
        // Update client statistics
        if (!unit.assigned_client_id.empty()) {
            stats.client_units_completed[unit.assigned_client_id]++;
            
            // Calculate processing time
            auto processing_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                unit.completed_time - unit.started_time).count();
            stats.client_average_processing_time_ms[unit.assigned_client_id] = 
                (stats.client_average_processing_time_ms[unit.assigned_client_id] + processing_time) / 2.0;
        }
    } else {
        unit.status = WorkUnitStatus::FAILED;
        stats.total_units_failed++;
        stats.failed_units_count++;
        stats.processing_units_count--;
        
        // Update client statistics
        if (!unit.assigned_client_id.empty()) {
            stats.client_units_failed[unit.assigned_client_id]++;
        }
        
        // Retry if enabled and retries remaining
        if (enable_retry && unit.retry_count < unit.max_retries) {
            retryFailedWorkUnit(unit_id);
        }
    }
    
    return true;
}

// Queue management
size_t FGCom_WorkUnitDistributor::getPendingUnitsCount() {
    return stats.pending_units_count.load();
}

size_t FGCom_WorkUnitDistributor::getProcessingUnitsCount() {
    return stats.processing_units_count.load();
}

size_t FGCom_WorkUnitDistributor::getCompletedUnitsCount() {
    return stats.completed_units_count.load();
}

size_t FGCom_WorkUnitDistributor::getFailedUnitsCount() {
    return stats.failed_units_count.load();
}

std::vector<std::string> FGCom_WorkUnitDistributor::getPendingUnits() {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    std::vector<std::string> pending_units;
    for (const auto& pair : work_units) {
        if (pair.second.status == WorkUnitStatus::PENDING) {
            pending_units.push_back(pair.first);
        }
    }
    
    return pending_units;
}

std::vector<std::string> FGCom_WorkUnitDistributor::getProcessingUnits() {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    std::vector<std::string> processing_units;
    for (const auto& pair : work_units) {
        if (pair.second.status == WorkUnitStatus::PROCESSING) {
            processing_units.push_back(pair.first);
        }
    }
    
    return processing_units;
}

std::vector<std::string> FGCom_WorkUnitDistributor::getCompletedUnits() {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    std::vector<std::string> completed_units;
    for (const auto& pair : work_units) {
        if (pair.second.status == WorkUnitStatus::COMPLETED) {
            completed_units.push_back(pair.first);
        }
    }
    
    return completed_units;
}

std::vector<std::string> FGCom_WorkUnitDistributor::getFailedUnits() {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    std::vector<std::string> failed_units;
    for (const auto& pair : work_units) {
        if (pair.second.status == WorkUnitStatus::FAILED || pair.second.status == WorkUnitStatus::TIMEOUT) {
            failed_units.push_back(pair.first);
        }
    }
    
    return failed_units;
}

// Statistics and monitoring
const WorkUnitDistributionStats& FGCom_WorkUnitDistributor::getStatistics() {
    return stats;
}

void FGCom_WorkUnitDistributor::resetStatistics() {
    stats.total_units_created = 0;
    stats.total_units_completed = 0;
    stats.total_units_failed = 0;
    stats.total_units_timeout = 0;
    stats.average_processing_time_ms = 0.0;
    stats.average_queue_wait_time_ms = 0.0;
    stats.distribution_efficiency_percent = 0.0;
    stats.pending_units_count = 0;
    stats.processing_units_count = 0;
    stats.completed_units_count = 0;
    stats.failed_units_count = 0;
    stats.client_units_completed.clear();
    stats.client_units_failed.clear();
    stats.client_average_processing_time_ms.clear();
}

std::map<std::string, double> FGCom_WorkUnitDistributor::getClientPerformanceMetrics() {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    std::map<std::string, double> metrics;
    for (const auto& pair : client_capabilities) {
        const std::string& client_id = pair.first;
        const ClientWorkUnitCapability& capability = pair.second;
        
        double efficiency = 0.0;
        if (stats.client_units_completed[client_id] > 0) {
            double total_units = stats.client_units_completed[client_id] + stats.client_units_failed[client_id];
            efficiency = (stats.client_units_completed[client_id] / total_units) * 100.0;
        }
        
        metrics[client_id + "_efficiency"] = efficiency;
        metrics[client_id + "_avg_processing_time"] = stats.client_average_processing_time_ms[client_id];
        metrics[client_id + "_active_units"] = capability.active_units.load();
        metrics[client_id + "_memory_usage"] = capability.memory_usage_mb.load();
        metrics[client_id + "_cpu_utilization"] = capability.cpu_utilization_percent.load();
        metrics[client_id + "_gpu_utilization"] = capability.gpu_utilization_percent.load();
    }
    
    return metrics;
}

std::map<WorkUnitType, uint64_t> FGCom_WorkUnitDistributor::getWorkUnitTypeStatistics() {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    std::map<WorkUnitType, uint64_t> type_stats;
    for (const auto& pair : work_units) {
        type_stats[pair.second.type]++;
    }
    
    return type_stats;
}

// Utility methods
void FGCom_WorkUnitDistributor::cleanup() {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto now = std::chrono::system_clock::now();
    auto cleanup_threshold = now - std::chrono::hours(24); // Keep units for 24 hours
    
    std::vector<std::string> units_to_remove;
    for (const auto& pair : work_units) {
        if (pair.second.completed_time < cleanup_threshold) {
            units_to_remove.push_back(pair.first);
        }
    }
    
    for (const std::string& unit_id : units_to_remove) {
        work_units.erase(unit_id);
    }
}

void FGCom_WorkUnitDistributor::forceCleanup() {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    // Remove all completed and failed units
    std::vector<std::string> units_to_remove;
    for (const auto& pair : work_units) {
        if (pair.second.status == WorkUnitStatus::COMPLETED || 
            pair.second.status == WorkUnitStatus::FAILED ||
            pair.second.status == WorkUnitStatus::TIMEOUT) {
            units_to_remove.push_back(pair.first);
        }
    }
    
    for (const std::string& unit_id : units_to_remove) {
        work_units.erase(unit_id);
    }
}

bool FGCom_WorkUnitDistributor::isHealthy() {
    return distribution_enabled && workers_running;
}

std::string FGCom_WorkUnitDistributor::getStatusReport() {
    std::stringstream ss;
    ss << "Work Unit Distributor Status:\n";
    ss << "  Enabled: " << (distribution_enabled ? "Yes" : "No") << "\n";
    ss << "  Workers Running: " << (workers_running ? "Yes" : "No") << "\n";
    ss << "  Pending Units: " << stats.pending_units_count.load() << "\n";
    ss << "  Processing Units: " << stats.processing_units_count.load() << "\n";
    ss << "  Completed Units: " << stats.completed_units_count.load() << "\n";
    ss << "  Failed Units: " << stats.failed_units_count.load() << "\n";
    ss << "  Total Created: " << stats.total_units_created.load() << "\n";
    ss << "  Total Completed: " << stats.total_units_completed.load() << "\n";
    ss << "  Total Failed: " << stats.total_units_failed.load() << "\n";
    ss << "  Distribution Efficiency: " << stats.distribution_efficiency_percent.load() << "%\n";
    
    return ss.str();
}

// Private methods
void FGCom_WorkUnitDistributor::workerThreadFunction() {
    while (workers_running) {
        std::unique_lock<std::mutex> lock(queue_mutex);
        
        // Wait for work or timeout
        queue_condition.wait_for(lock, std::chrono::milliseconds(1000));
        
        if (!workers_running) {
            break;
        }
        
        // Process pending units
        std::vector<std::string> units_to_process;
        {
            std::lock_guard<std::mutex> units_lock(units_mutex);
            
            while (!pending_units_queue.empty() && units_to_process.size() < static_cast<size_t>(max_concurrent_units)) {
                std::string unit_id = pending_units_queue.front();
                pending_units_queue.pop();
                
                auto it = work_units.find(unit_id);
                if (it != work_units.end() && it->second.status == WorkUnitStatus::PENDING) {
                    units_to_process.push_back(unit_id);
                }
            }
        }
        
        // Process each unit
        for (const std::string& unit_id : units_to_process) {
            distributeWorkUnit(unit_id);
        }
        
        // Check for timeouts
        checkTimeouts();
        
        // Cleanup old units
        cleanupCompletedUnits();
    }
}

std::string FGCom_WorkUnitDistributor::selectOptimalClient(const WorkUnit& unit) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    std::string best_client;
    double best_score = -1.0;
    
    for (const auto& pair : client_capabilities) {
        if (!pair.second.is_online) {
            continue;
        }
        
        // Check if client supports this work unit type
        if (std::find(pair.second.supported_types.begin(), 
                     pair.second.supported_types.end(), unit.type) == pair.second.supported_types.end()) {
            continue;
        }
        
        // Check if client has capacity
        if (pair.second.active_units.load() >= pair.second.max_concurrent_units.at(unit.type)) {
            continue;
        }
        
        // Check memory requirements
        if (unit.memory_requirement_mb > pair.second.max_memory_mb - pair.second.memory_usage_mb.load()) {
            continue;
        }
        
        // Calculate client score
        double score = calculateClientScore(pair.first, unit);
        if (score > best_score) {
            best_score = score;
            best_client = pair.first;
        }
    }
    
    return best_client;
}

double FGCom_WorkUnitDistributor::calculateClientScore(const std::string& client_id, const WorkUnit& unit) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_capabilities.find(client_id);
    if (it == client_capabilities.end()) {
        return 0.0;
    }
    
    const ClientWorkUnitCapability& capability = it->second;
    
    // Base score from processing speed multiplier
    double score = capability.processing_speed_multiplier.at(unit.type);
    
    // Penalize for high load
    double load_factor = 1.0 - (capability.active_units.load() / static_cast<double>(capability.max_concurrent_units.at(unit.type)));
    score *= load_factor;
    
    // Penalize for high memory usage
    double memory_factor = 1.0 - (capability.memory_usage_mb.load() / static_cast<double>(capability.max_memory_mb));
    score *= memory_factor;
    
    // Penalize for high CPU utilization
    double cpu_factor = 1.0 - (capability.cpu_utilization_percent.load() / 100.0);
    score *= cpu_factor;
    
    // Penalize for high GPU utilization (if GPU required)
    if (unit.requires_gpu) {
        double gpu_factor = 1.0 - (capability.gpu_utilization_percent.load() / 100.0);
        score *= gpu_factor;
    }
    
    // Bonus for low latency
    double latency_factor = 1.0 / (1.0 + capability.processing_latency_ms / 1000.0);
    score *= latency_factor;
    
    return score;
}

bool FGCom_WorkUnitDistributor::assignWorkUnit(const std::string& unit_id, const std::string& client_id) {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto it = work_units.find(unit_id);
    if (it == work_units.end()) {
        return false;
    }
    
    WorkUnit& unit = it->second;
    
    // Get client capability
    std::lock_guard<std::mutex> clients_lock(clients_mutex);
    auto client_it = client_capabilities.find(client_id);
    if (client_it == client_capabilities.end()) {
        return false;
    }
    
    // Use modular sharing interface to share the work unit
    if (sharing_manager) {
        WorkUnitSharingResult share_result = shareWorkUnitWithClient(unit_id, client_id);
        if (share_result != WorkUnitSharingResult::SUCCESS) {
            return false;
        }
    }
    
    unit.status = WorkUnitStatus::ASSIGNED;
    unit.assigned_client_id = client_id;
    unit.assigned_time = std::chrono::system_clock::now();
    
    // Add to client's assigned units
    client_assigned_units[client_id].push_back(unit_id);
    
    // Update statistics
    stats.pending_units_count--;
    stats.processing_units_count++;
    
    return true;
}

void FGCom_WorkUnitDistributor::processCompletedWorkUnit(const std::string& unit_id, bool success, const std::string& error_message) {
    // This method is called by processWorkUnitResult
    // Implementation is already in processWorkUnitResult
}

void FGCom_WorkUnitDistributor::handleWorkUnitTimeout(const std::string& unit_id) {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto it = work_units.find(unit_id);
    if (it == work_units.end()) {
        return;
    }
    
    WorkUnit& unit = it->second;
    if (unit.status == WorkUnitStatus::PROCESSING) {
        unit.status = WorkUnitStatus::TIMEOUT;
        unit.error_message = "Processing timeout";
        stats.total_units_timeout++;
        stats.processing_units_count--;
        stats.failed_units_count++;
        
        // Remove from client assignment
        if (!unit.assigned_client_id.empty()) {
            auto client_it = client_assigned_units.find(unit.assigned_client_id);
            if (client_it != client_assigned_units.end()) {
                auto& assigned = client_it->second;
                assigned.erase(std::remove(assigned.begin(), assigned.end(), unit_id), assigned.end());
            }
        }
    }
}

void FGCom_WorkUnitDistributor::retryFailedWorkUnit(const std::string& unit_id) {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto it = work_units.find(unit_id);
    if (it == work_units.end()) {
        return;
    }
    
    WorkUnit& unit = it->second;
    if (unit.status == WorkUnitStatus::FAILED && unit.retry_count < unit.max_retries) {
        unit.status = WorkUnitStatus::PENDING;
        unit.retry_count++;
        unit.next_retry_time = std::chrono::system_clock::now() + std::chrono::milliseconds(retry_delay_ms);
        unit.assigned_client_id.clear();
        unit.error_message.clear();
        
        // Add back to pending queue
        pending_units_queue.push(unit_id);
        stats.pending_units_count++;
        stats.failed_units_count--;
    }
}

void FGCom_WorkUnitDistributor::cleanupCompletedUnits() {
    // This method is called by workerThreadFunction
    // Implementation is already in cleanup()
}

void FGCom_WorkUnitDistributor::checkTimeouts() {
    std::lock_guard<std::mutex> lock(units_mutex);
    
    auto now = std::chrono::system_clock::now();
    
    for (auto& pair : work_units) {
        WorkUnit& unit = pair.second;
        if (unit.status == WorkUnitStatus::PROCESSING) {
            auto processing_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - unit.started_time).count();
            
            if (processing_time > unit.max_processing_time_ms) {
                handleWorkUnitTimeout(pair.first);
            }
        }
    }
}

// Work unit sharing implementation (modular)
WorkUnitSharingResult FGCom_WorkUnitDistributor::shareWorkUnitWithClient(
    const std::string& unit_id, 
    const std::string& client_id) {
    
    if (!sharing_manager) {
        return WorkUnitSharingResult::SHARING_DISABLED;
    }
    
    std::lock_guard<std::mutex> units_lock(units_mutex);
    std::lock_guard<std::mutex> clients_lock(clients_mutex);
    
    auto unit_it = work_units.find(unit_id);
    if (unit_it == work_units.end()) {
        return WorkUnitSharingResult::INVALID_UNIT;
    }
    
    auto client_it = client_capabilities.find(client_id);
    if (client_it == client_capabilities.end()) {
        return WorkUnitSharingResult::CLIENT_NOT_AVAILABLE;
    }
    
    const WorkUnit& unit = unit_it->second;
    const ClientWorkUnitCapability& capability = client_it->second;
    
    return sharing_manager->shareWithClient(unit_id, unit, client_id, capability);
}

// Work unit sharing configuration methods
bool FGCom_WorkUnitDistributor::setSharingStrategy(const std::string& strategy_name) {
    if (!sharing_manager) {
        return false;
    }
    return sharing_manager->setStrategy(strategy_name);
}

std::string FGCom_WorkUnitDistributor::getSharingStrategy() const {
    if (!sharing_manager) {
        return "";
    }
    return sharing_manager->getCurrentStrategyName();
}

std::vector<std::string> FGCom_WorkUnitDistributor::getAvailableSharingStrategies() const {
    if (!sharing_manager) {
        return std::vector<std::string>();
    }
    return sharing_manager->getAvailableStrategies();
}

WorkUnitSharingStats FGCom_WorkUnitDistributor::getSharingStatistics() const {
    if (!sharing_manager) {
        return WorkUnitSharingStats();
    }
    return sharing_manager->getStatistics();
}

// Work unit factory implementation
std::string FGCom_WorkUnitFactory::createPropagationGridUnit(
    const std::vector<double>& grid_points,
    double frequency_mhz,
    double tx_power_watts,
    const std::map<std::string, double>& propagation_params) {
    
    auto& distributor = FGCom_WorkUnitDistributor::getInstance();
    
    // Prepare input data
    std::vector<double> input_data = grid_points;
    input_data.push_back(frequency_mhz);
    input_data.push_back(tx_power_watts);
    
    // Add propagation parameters
    std::map<std::string, double> parameters = propagation_params;
    parameters["frequency_mhz"] = frequency_mhz;
    parameters["tx_power_watts"] = tx_power_watts;
    
    return distributor.createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
}

std::string FGCom_WorkUnitFactory::createAntennaPatternUnit(
    const std::vector<double>& antenna_data,
    double frequency_mhz,
    const std::map<std::string, double>& antenna_params) {
    
    auto& distributor = FGCom_WorkUnitDistributor::getInstance();
    
    // Prepare input data
    std::vector<double> input_data = antenna_data;
    input_data.push_back(frequency_mhz);
    
    // Add antenna parameters
    std::map<std::string, double> parameters = antenna_params;
    parameters["frequency_mhz"] = frequency_mhz;
    
    return distributor.createWorkUnit(WorkUnitType::ANTENNA_PATTERN, input_data, parameters);
}

std::string FGCom_WorkUnitFactory::createBatchQSOUnit(
    const std::vector<std::vector<double>>& qso_data,
    double frequency_mhz,
    const std::map<std::string, double>& batch_params) {
    
    auto& distributor = FGCom_WorkUnitDistributor::getInstance();
    
    // Flatten QSO data
    std::vector<double> input_data;
    for (const auto& qso : qso_data) {
        input_data.insert(input_data.end(), qso.begin(), qso.end());
    }
    input_data.push_back(frequency_mhz);
    
    // Add batch parameters
    std::map<std::string, double> parameters = batch_params;
    parameters["frequency_mhz"] = frequency_mhz;
    parameters["qso_count"] = qso_data.size();
    
    return distributor.createWorkUnit(WorkUnitType::BATCH_QSO, input_data, parameters);
}

std::string FGCom_WorkUnitFactory::createSolarEffectsUnit(
    const std::vector<double>& solar_data,
    double frequency_mhz,
    const std::map<std::string, double>& solar_params) {
    
    auto& distributor = FGCom_WorkUnitDistributor::getInstance();
    
    // Prepare input data
    std::vector<double> input_data = solar_data;
    input_data.push_back(frequency_mhz);
    
    // Add solar parameters
    std::map<std::string, double> parameters = solar_params;
    parameters["frequency_mhz"] = frequency_mhz;
    
    return distributor.createWorkUnit(WorkUnitType::SOLAR_EFFECTS, input_data, parameters);
}
