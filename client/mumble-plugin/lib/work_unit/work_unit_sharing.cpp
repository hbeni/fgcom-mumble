/*
 * Work Unit Sharing Implementation
 * 
 * This file implements modular work unit sharing strategies for propagation
 * calculations. The sharing mechanism is now modular and can be swapped
 * or extended with different strategies.
 */

#include "work_unit/work_unit_sharing.h"
#include "work_unit_distributor.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <mutex>
#include <limits>

// Static empty stats for return when no strategy is set
static WorkUnitSharingStats empty_stats;

// Direct Assignment Sharing Strategy Implementation
FGCom_DirectAssignmentSharingStrategy::FGCom_DirectAssignmentSharingStrategy() {
    stats.total_units_shared = 0;
    stats.total_units_failed = 0;
    stats.total_broadcasts = 0;
    stats.total_direct_assignments = 0;
    stats.average_sharing_time_ms = 0.0;
}

FGCom_DirectAssignmentSharingStrategy::~FGCom_DirectAssignmentSharingStrategy() {
    shutdown();
}

bool FGCom_DirectAssignmentSharingStrategy::initialize() {
    return true;
}

void FGCom_DirectAssignmentSharingStrategy::shutdown() {
    std::lock_guard<std::mutex> lock(availability_mutex);
    client_availability.clear();
}

WorkUnitSharingResult FGCom_DirectAssignmentSharingStrategy::shareWithClient(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::string& client_id,
    const ClientWorkUnitCapability& client_capability) {
    
    auto start_time = std::chrono::system_clock::now();
    
    // Check if client is available
    {
        std::lock_guard<std::mutex> lock(availability_mutex);
        if (client_availability.find(client_id) != client_availability.end() && 
            !client_availability.at(client_id)) {
            if (on_failed_callback) {
                on_failed_callback(unit_id, client_id, WorkUnitSharingResult::CLIENT_NOT_AVAILABLE);
            }
            return WorkUnitSharingResult::CLIENT_NOT_AVAILABLE;
        }
    }
    
    // Check if client supports this work unit type
    bool supports_type = false;
    for (const auto& type : client_capability.supported_types) {
        if (type == unit.type) {
            supports_type = true;
            break;
        }
    }
    
    if (!supports_type) {
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.total_units_failed++;
        }
        if (on_failed_callback) {
            on_failed_callback(unit_id, client_id, WorkUnitSharingResult::FAILED);
        }
        return WorkUnitSharingResult::FAILED;
    }
    
    // Perform the actual sharing (this would be implemented based on communication mechanism)
    // For now, we simulate successful sharing
    
    auto end_time = std::chrono::system_clock::now();
    auto sharing_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.total_units_shared++;
        stats.total_direct_assignments++;
        stats.client_units_received[client_id]++;
        
        // Update average sharing time
        double current_avg = stats.average_sharing_time_ms.load();
        uint64_t total = stats.total_units_shared.load();
        stats.average_sharing_time_ms = ((current_avg * (total - 1)) + sharing_time) / total;
    }
    
    if (on_shared_callback) {
        on_shared_callback(unit_id, client_id);
    }
    
    return WorkUnitSharingResult::SUCCESS;
}

WorkUnitSharingResult FGCom_DirectAssignmentSharingStrategy::shareWithClients(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::vector<std::string>& client_ids,
    const std::map<std::string, ClientWorkUnitCapability>& client_capabilities) {
    
    // Direct assignment strategy only shares with one client at a time
    // Select the first available client
    for (const auto& client_id : client_ids) {
        auto it = client_capabilities.find(client_id);
        if (it != client_capabilities.end()) {
            WorkUnitSharingResult result = shareWithClient(unit_id, unit, client_id, it->second);
            if (result == WorkUnitSharingResult::SUCCESS) {
                return result;
            }
        }
    }
    
    return WorkUnitSharingResult::CLIENT_NOT_AVAILABLE;
}

WorkUnitSharingResult FGCom_DirectAssignmentSharingStrategy::shareWithAllClients(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::map<std::string, ClientWorkUnitCapability>& all_client_capabilities) {
    
    // Direct assignment strategy shares with the first available client
    for (const auto& pair : all_client_capabilities) {
        WorkUnitSharingResult result = shareWithClient(unit_id, unit, pair.first, pair.second);
        if (result == WorkUnitSharingResult::SUCCESS) {
            return result;
        }
    }
    
    return WorkUnitSharingResult::CLIENT_NOT_AVAILABLE;
}

bool FGCom_DirectAssignmentSharingStrategy::isClientAvailable(const std::string& client_id) const {
    std::lock_guard<std::mutex> lock(availability_mutex);
    auto it = client_availability.find(client_id);
    if (it == client_availability.end()) {
        return true; // Assume available if not tracked
    }
    return it->second;
}

const WorkUnitSharingStats& FGCom_DirectAssignmentSharingStrategy::getStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    return stats;
}

void FGCom_DirectAssignmentSharingStrategy::resetStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.total_units_shared = 0;
    stats.total_units_failed = 0;
    stats.total_broadcasts = 0;
    stats.total_direct_assignments = 0;
    stats.average_sharing_time_ms = 0.0;
    stats.client_units_received.clear();
    stats.client_units_failed.clear();
}

std::string FGCom_DirectAssignmentSharingStrategy::getStrategyName() const {
    return "direct_assignment";
}

void FGCom_DirectAssignmentSharingStrategy::setOnSharedCallback(
    std::function<void(const std::string&, const std::string&)> callback) {
    on_shared_callback = callback;
}

void FGCom_DirectAssignmentSharingStrategy::setOnFailedCallback(
    std::function<void(const std::string&, const std::string&, WorkUnitSharingResult)> callback) {
    on_failed_callback = callback;
}

void FGCom_DirectAssignmentSharingStrategy::updateClientAvailability(const std::string& client_id, bool available) {
    std::lock_guard<std::mutex> lock(availability_mutex);
    client_availability[client_id] = available;
}

// Broadcast Sharing Strategy Implementation
FGCom_BroadcastSharingStrategy::FGCom_BroadcastSharingStrategy(int max_clients)
    : max_broadcast_clients(max_clients) {
    stats.total_units_shared = 0;
    stats.total_units_failed = 0;
    stats.total_broadcasts = 0;
    stats.total_direct_assignments = 0;
    stats.average_sharing_time_ms = 0.0;
}

FGCom_BroadcastSharingStrategy::~FGCom_BroadcastSharingStrategy() {
    shutdown();
}

bool FGCom_BroadcastSharingStrategy::initialize() {
    return true;
}

void FGCom_BroadcastSharingStrategy::shutdown() {
    std::lock_guard<std::mutex> lock(availability_mutex);
    client_availability.clear();
}

WorkUnitSharingResult FGCom_BroadcastSharingStrategy::shareWithClient(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::string& client_id,
    const ClientWorkUnitCapability& client_capability) {
    
    // Broadcast strategy can share with a single client too
    std::vector<std::string> client_ids = {client_id};
    std::map<std::string, ClientWorkUnitCapability> capabilities;
    // Manually copy capability to avoid atomic copy assignment
    ClientWorkUnitCapability& cap = capabilities[client_id];
    cap.client_id = client_capability.client_id;
    cap.supported_types = client_capability.supported_types;
    cap.max_concurrent_units = client_capability.max_concurrent_units;
    cap.processing_speed_multiplier = client_capability.processing_speed_multiplier;
    cap.max_memory_mb = client_capability.max_memory_mb;
    cap.supports_gpu = client_capability.supports_gpu;
    cap.supports_double_precision = client_capability.supports_double_precision;
    cap.network_bandwidth_mbps = client_capability.network_bandwidth_mbps;
    cap.processing_latency_ms = client_capability.processing_latency_ms;
    cap.is_online = client_capability.is_online;
    cap.last_heartbeat = client_capability.last_heartbeat;
    cap.active_units.store(client_capability.active_units.load());
    cap.pending_units.store(client_capability.pending_units.load());
    cap.memory_usage_mb.store(client_capability.memory_usage_mb.load());
    cap.cpu_utilization_percent.store(client_capability.cpu_utilization_percent.load());
    cap.gpu_utilization_percent.store(client_capability.gpu_utilization_percent.load());
    return shareWithClients(unit_id, unit, client_ids, capabilities);
}

WorkUnitSharingResult FGCom_BroadcastSharingStrategy::shareWithClients(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::vector<std::string>& client_ids,
    const std::map<std::string, ClientWorkUnitCapability>& client_capabilities) {
    
    auto start_time = std::chrono::system_clock::now();
    int success_count = 0;
    int fail_count = 0;
    
    // Limit number of clients to broadcast to
    int clients_to_share = std::min(static_cast<int>(client_ids.size()), max_broadcast_clients);
    
    for (int i = 0; i < clients_to_share && i < static_cast<int>(client_ids.size()); i++) {
        const std::string& client_id = client_ids[i];
        
        // Check if client is available
        {
            std::lock_guard<std::mutex> lock(availability_mutex);
            if (client_availability.find(client_id) != client_availability.end() && 
                !client_availability.at(client_id)) {
                fail_count++;
                if (on_failed_callback) {
                    on_failed_callback(unit_id, client_id, WorkUnitSharingResult::CLIENT_NOT_AVAILABLE);
                }
                continue;
            }
        }
        
        auto it = client_capabilities.find(client_id);
        if (it == client_capabilities.end()) {
            fail_count++;
            continue;
        }
        
        // Check if client supports this work unit type
        bool supports_type = false;
        for (const auto& type : it->second.supported_types) {
            if (type == unit.type) {
                supports_type = true;
                break;
            }
        }
        
        if (!supports_type) {
            fail_count++;
            if (on_failed_callback) {
                on_failed_callback(unit_id, client_id, WorkUnitSharingResult::FAILED);
            }
            continue;
        }
        
        // Perform the actual sharing
        success_count++;
        
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.client_units_received[client_id]++;
        }
        
        if (on_shared_callback) {
            on_shared_callback(unit_id, client_id);
        }
    }
    
    auto end_time = std::chrono::system_clock::now();
    auto sharing_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.total_units_shared += success_count;
        stats.total_units_failed += fail_count;
        stats.total_broadcasts++;
        
        if (success_count > 0) {
            double current_avg = stats.average_sharing_time_ms.load();
            uint64_t total = stats.total_units_shared.load();
            stats.average_sharing_time_ms = ((current_avg * (total - success_count)) + sharing_time) / total;
        }
    }
    
    return success_count > 0 ? WorkUnitSharingResult::SUCCESS : WorkUnitSharingResult::FAILED;
}

WorkUnitSharingResult FGCom_BroadcastSharingStrategy::shareWithAllClients(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::map<std::string, ClientWorkUnitCapability>& all_client_capabilities) {
    
    std::vector<std::string> client_ids;
    for (const auto& pair : all_client_capabilities) {
        client_ids.push_back(pair.first);
    }
    
    return shareWithClients(unit_id, unit, client_ids, all_client_capabilities);
}

bool FGCom_BroadcastSharingStrategy::isClientAvailable(const std::string& client_id) const {
    std::lock_guard<std::mutex> lock(availability_mutex);
    auto it = client_availability.find(client_id);
    if (it == client_availability.end()) {
        return true;
    }
    return it->second;
}

const WorkUnitSharingStats& FGCom_BroadcastSharingStrategy::getStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    return stats;
}

void FGCom_BroadcastSharingStrategy::resetStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.total_units_shared = 0;
    stats.total_units_failed = 0;
    stats.total_broadcasts = 0;
    stats.total_direct_assignments = 0;
    stats.average_sharing_time_ms = 0.0;
    stats.client_units_received.clear();
    stats.client_units_failed.clear();
}

std::string FGCom_BroadcastSharingStrategy::getStrategyName() const {
    return "broadcast";
}

void FGCom_BroadcastSharingStrategy::setOnSharedCallback(
    std::function<void(const std::string&, const std::string&)> callback) {
    on_shared_callback = callback;
}

void FGCom_BroadcastSharingStrategy::setOnFailedCallback(
    std::function<void(const std::string&, const std::string&, WorkUnitSharingResult)> callback) {
    on_failed_callback = callback;
}

void FGCom_BroadcastSharingStrategy::updateClientAvailability(const std::string& client_id, bool available) {
    std::lock_guard<std::mutex> lock(availability_mutex);
    client_availability[client_id] = available;
}

void FGCom_BroadcastSharingStrategy::setMaxBroadcastClients(int max_clients) {
    max_broadcast_clients = max_clients;
}

// Load Balancing Sharing Strategy Implementation
FGCom_LoadBalancingSharingStrategy::FGCom_LoadBalancingSharingStrategy() {
    stats.total_units_shared = 0;
    stats.total_units_failed = 0;
    stats.total_broadcasts = 0;
    stats.total_direct_assignments = 0;
    stats.average_sharing_time_ms = 0.0;
}

FGCom_LoadBalancingSharingStrategy::~FGCom_LoadBalancingSharingStrategy() {
    shutdown();
}

bool FGCom_LoadBalancingSharingStrategy::initialize() {
    return true;
}

void FGCom_LoadBalancingSharingStrategy::shutdown() {
    std::lock_guard<std::mutex> lock(availability_mutex);
    std::lock_guard<std::mutex> load_lock(load_mutex);
    client_availability.clear();
    client_load.clear();
}

WorkUnitSharingResult FGCom_LoadBalancingSharingStrategy::shareWithClient(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::string& client_id,
    const ClientWorkUnitCapability& client_capability) {
    
    // Load balancing strategy selects the best client automatically
    std::map<std::string, ClientWorkUnitCapability> capabilities;
    // Manually copy capability to avoid atomic copy assignment
    ClientWorkUnitCapability& cap = capabilities[client_id];
    cap.client_id = client_capability.client_id;
    cap.supported_types = client_capability.supported_types;
    cap.max_concurrent_units = client_capability.max_concurrent_units;
    cap.processing_speed_multiplier = client_capability.processing_speed_multiplier;
    cap.max_memory_mb = client_capability.max_memory_mb;
    cap.supports_gpu = client_capability.supports_gpu;
    cap.supports_double_precision = client_capability.supports_double_precision;
    cap.network_bandwidth_mbps = client_capability.network_bandwidth_mbps;
    cap.processing_latency_ms = client_capability.processing_latency_ms;
    cap.is_online = client_capability.is_online;
    cap.last_heartbeat = client_capability.last_heartbeat;
    cap.active_units.store(client_capability.active_units.load());
    cap.pending_units.store(client_capability.pending_units.load());
    cap.memory_usage_mb.store(client_capability.memory_usage_mb.load());
    cap.cpu_utilization_percent.store(client_capability.cpu_utilization_percent.load());
    cap.gpu_utilization_percent.store(client_capability.gpu_utilization_percent.load());
    std::string best_client = selectBestClient(capabilities);
    
    if (best_client.empty()) {
        return WorkUnitSharingResult::CLIENT_NOT_AVAILABLE;
    }
    
    // Use direct assignment logic
    auto start_time = std::chrono::system_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(availability_mutex);
        if (client_availability.find(best_client) != client_availability.end() && 
            !client_availability.at(best_client)) {
            if (on_failed_callback) {
                on_failed_callback(unit_id, best_client, WorkUnitSharingResult::CLIENT_NOT_AVAILABLE);
            }
            return WorkUnitSharingResult::CLIENT_NOT_AVAILABLE;
        }
    }
    
    // Check if client supports this work unit type
    bool supports_type = false;
    for (const auto& type : client_capability.supported_types) {
        if (type == unit.type) {
            supports_type = true;
            break;
        }
    }
    
    if (!supports_type) {
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.total_units_failed++;
        }
        if (on_failed_callback) {
            on_failed_callback(unit_id, best_client, WorkUnitSharingResult::FAILED);
        }
        return WorkUnitSharingResult::FAILED;
    }
    
    // Update client load
    {
        std::lock_guard<std::mutex> lock(load_mutex);
        client_load[best_client]++;
    }
    
    auto end_time = std::chrono::system_clock::now();
    auto sharing_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.total_units_shared++;
        stats.total_direct_assignments++;
        stats.client_units_received[best_client]++;
        
        double current_avg = stats.average_sharing_time_ms.load();
        uint64_t total = stats.total_units_shared.load();
        stats.average_sharing_time_ms = ((current_avg * (total - 1)) + sharing_time) / total;
    }
    
    if (on_shared_callback) {
        on_shared_callback(unit_id, best_client);
    }
    
    return WorkUnitSharingResult::SUCCESS;
}

WorkUnitSharingResult FGCom_LoadBalancingSharingStrategy::shareWithClients(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::vector<std::string>& client_ids,
    const std::map<std::string, ClientWorkUnitCapability>& client_capabilities) {
    
    // Select best client based on load
    std::string best_client = selectBestClient(client_capabilities);
    
    if (best_client.empty()) {
        return WorkUnitSharingResult::CLIENT_NOT_AVAILABLE;
    }
    
    auto it = client_capabilities.find(best_client);
    if (it == client_capabilities.end()) {
        return WorkUnitSharingResult::CLIENT_NOT_AVAILABLE;
    }
    
    return shareWithClient(unit_id, unit, best_client, it->second);
}

WorkUnitSharingResult FGCom_LoadBalancingSharingStrategy::shareWithAllClients(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::map<std::string, ClientWorkUnitCapability>& all_client_capabilities) {
    
    return shareWithClients(unit_id, unit, std::vector<std::string>(), all_client_capabilities);
}

bool FGCom_LoadBalancingSharingStrategy::isClientAvailable(const std::string& client_id) const {
    std::lock_guard<std::mutex> lock(availability_mutex);
    auto it = client_availability.find(client_id);
    if (it == client_availability.end()) {
        return true;
    }
    return it->second;
}

const WorkUnitSharingStats& FGCom_LoadBalancingSharingStrategy::getStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    return stats;
}

void FGCom_LoadBalancingSharingStrategy::resetStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.total_units_shared = 0;
    stats.total_units_failed = 0;
    stats.total_broadcasts = 0;
    stats.total_direct_assignments = 0;
    stats.average_sharing_time_ms = 0.0;
    stats.client_units_received.clear();
    stats.client_units_failed.clear();
}

std::string FGCom_LoadBalancingSharingStrategy::getStrategyName() const {
    return "load_balancing";
}

void FGCom_LoadBalancingSharingStrategy::setOnSharedCallback(
    std::function<void(const std::string&, const std::string&)> callback) {
    on_shared_callback = callback;
}

void FGCom_LoadBalancingSharingStrategy::setOnFailedCallback(
    std::function<void(const std::string&, const std::string&, WorkUnitSharingResult)> callback) {
    on_failed_callback = callback;
}

void FGCom_LoadBalancingSharingStrategy::updateClientAvailability(const std::string& client_id, bool available) {
    std::lock_guard<std::mutex> lock(availability_mutex);
    client_availability[client_id] = available;
}

void FGCom_LoadBalancingSharingStrategy::updateClientLoad(const std::string& client_id, int load) {
    std::lock_guard<std::mutex> lock(load_mutex);
    client_load[client_id] = load;
}

std::string FGCom_LoadBalancingSharingStrategy::selectBestClient(
    const std::map<std::string, ClientWorkUnitCapability>& client_capabilities) const {
    
    std::string best_client;
    int lowest_load = std::numeric_limits<int>::max();
    
    std::lock_guard<std::mutex> load_lock(load_mutex);
    std::lock_guard<std::mutex> avail_lock(availability_mutex);
    
    for (const auto& pair : client_capabilities) {
        const std::string& client_id = pair.first;
        
        // Check availability
        if (client_availability.find(client_id) != client_availability.end() && 
            !client_availability.at(client_id)) {
            continue;
        }
        
        // Get current load
        int load = 0;
        if (client_load.find(client_id) != client_load.end()) {
            load = client_load.at(client_id);
        }
        
        // Consider client's max concurrent units capacity
        int max_capacity = 10; // Default
        if (pair.second.max_concurrent_units.find(WorkUnitType::PROPAGATION_GRID) != 
            pair.second.max_concurrent_units.end()) {
            max_capacity = pair.second.max_concurrent_units.at(WorkUnitType::PROPAGATION_GRID);
        }
        
        // Calculate effective load (normalized)
        double effective_load = static_cast<double>(load) / max_capacity;
        
        if (effective_load < lowest_load) {
            lowest_load = effective_load;
            best_client = client_id;
        }
    }
    
    return best_client;
}

// Work Unit Sharing Manager Implementation
std::unique_ptr<FGCom_WorkUnitSharingManager> FGCom_WorkUnitSharingManager::instance = nullptr;
std::mutex FGCom_WorkUnitSharingManager::instance_mutex;

FGCom_WorkUnitSharingManager& FGCom_WorkUnitSharingManager::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::make_unique<FGCom_WorkUnitSharingManager>();
    }
    return *instance;
}

void FGCom_WorkUnitSharingManager::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (instance) {
        instance->shutdown();
        instance.reset();
    }
}

bool FGCom_WorkUnitSharingManager::initialize(const std::string& default_strategy) {
    std::lock_guard<std::mutex> lock(strategy_mutex);
    
    // Register built-in strategies
    registerStrategy("direct", std::make_unique<FGCom_DirectAssignmentSharingStrategy>());
    registerStrategy("broadcast", std::make_unique<FGCom_BroadcastSharingStrategy>());
    registerStrategy("load_balancing", std::make_unique<FGCom_LoadBalancingSharingStrategy>());
    
    default_strategy_name = default_strategy;
    return setStrategy(default_strategy);
}

void FGCom_WorkUnitSharingManager::shutdown() {
    std::lock_guard<std::mutex> lock(strategy_mutex);
    if (current_strategy) {
        current_strategy->shutdown();
        current_strategy.reset();
    }
    available_strategies.clear();
}

bool FGCom_WorkUnitSharingManager::registerStrategy(
    const std::string& name, 
    std::unique_ptr<FGCom_WorkUnitSharingStrategy> strategy) {
    
    std::lock_guard<std::mutex> lock(strategy_mutex);
    
    if (!strategy) {
        return false;
    }
    
    if (!strategy->initialize()) {
        return false;
    }
    
    available_strategies[name] = std::move(strategy);
    return true;
}

bool FGCom_WorkUnitSharingManager::setStrategy(const std::string& strategy_name) {
    std::lock_guard<std::mutex> lock(strategy_mutex);
    
    auto it = available_strategies.find(strategy_name);
    if (it == available_strategies.end()) {
        return false;
    }
    
    if (current_strategy) {
        current_strategy->shutdown();
    }
    
    // Create a new instance of the strategy (don't move from available_strategies)
    std::unique_ptr<FGCom_WorkUnitSharingStrategy> new_strategy;
    if (strategy_name == "direct") {
        new_strategy = std::make_unique<FGCom_DirectAssignmentSharingStrategy>();
    } else if (strategy_name == "broadcast") {
        new_strategy = std::make_unique<FGCom_BroadcastSharingStrategy>();
    } else if (strategy_name == "load_balancing") {
        new_strategy = std::make_unique<FGCom_LoadBalancingSharingStrategy>();
    } else {
        // For custom strategies, clone from available_strategies
        // This is a simplified approach - in production, strategies should be cloneable
        return false;
    }
    
    if (!new_strategy || !new_strategy->initialize()) {
        return false;
    }
    
    current_strategy = std::move(new_strategy);
    return true;
}

std::string FGCom_WorkUnitSharingManager::getCurrentStrategyName() const {
    std::lock_guard<std::mutex> lock(strategy_mutex);
    if (!current_strategy) {
        return "";
    }
    return current_strategy->getStrategyName();
}

std::vector<std::string> FGCom_WorkUnitSharingManager::getAvailableStrategies() const {
    std::lock_guard<std::mutex> lock(strategy_mutex);
    std::vector<std::string> strategies;
    for (const auto& pair : available_strategies) {
        strategies.push_back(pair.first);
    }
    return strategies;
}

WorkUnitSharingResult FGCom_WorkUnitSharingManager::shareWithClient(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::string& client_id,
    const ClientWorkUnitCapability& client_capability) {
    
    std::lock_guard<std::mutex> lock(strategy_mutex);
    if (!current_strategy) {
        return WorkUnitSharingResult::SHARING_DISABLED;
    }
    return current_strategy->shareWithClient(unit_id, unit, client_id, client_capability);
}

WorkUnitSharingResult FGCom_WorkUnitSharingManager::shareWithClients(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::vector<std::string>& client_ids,
    const std::map<std::string, ClientWorkUnitCapability>& client_capabilities) {
    
    std::lock_guard<std::mutex> lock(strategy_mutex);
    if (!current_strategy) {
        return WorkUnitSharingResult::SHARING_DISABLED;
    }
    return current_strategy->shareWithClients(unit_id, unit, client_ids, client_capabilities);
}

WorkUnitSharingResult FGCom_WorkUnitSharingManager::shareWithAllClients(
    const std::string& unit_id,
    const WorkUnit& unit,
    const std::map<std::string, ClientWorkUnitCapability>& all_client_capabilities) {
    
    std::lock_guard<std::mutex> lock(strategy_mutex);
    if (!current_strategy) {
        return WorkUnitSharingResult::SHARING_DISABLED;
    }
    return current_strategy->shareWithAllClients(unit_id, unit, all_client_capabilities);
}

bool FGCom_WorkUnitSharingManager::isClientAvailable(const std::string& client_id) const {
    std::lock_guard<std::mutex> lock(strategy_mutex);
    if (!current_strategy) {
        return false;
    }
    return current_strategy->isClientAvailable(client_id);
}

const WorkUnitSharingStats& FGCom_WorkUnitSharingManager::getStatistics() const {
    std::lock_guard<std::mutex> lock(strategy_mutex);
    if (!current_strategy) {
        return empty_stats;
    }
    return current_strategy->getStatistics();
}

void FGCom_WorkUnitSharingManager::resetStatistics() const {
    std::lock_guard<std::mutex> lock(strategy_mutex);
    if (current_strategy) {
        current_strategy->resetStatistics();
    }
}

FGCom_WorkUnitSharingStrategy* FGCom_WorkUnitSharingManager::getCurrentStrategy() const {
    std::lock_guard<std::mutex> lock(strategy_mutex);
    return current_strategy.get();
}

