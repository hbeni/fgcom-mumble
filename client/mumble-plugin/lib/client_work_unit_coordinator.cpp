/*
 * Client Work Unit Coordinator Implementation
 * 
 * This file implements the client-side work unit coordination system
 * for requesting, processing, and submitting work units to the server.
 */

#include "client_work_unit_coordinator.h"
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

// Static member definitions
std::unique_ptr<FGCom_ClientWorkUnitCoordinator> FGCom_ClientWorkUnitCoordinator::instance = nullptr;
std::mutex FGCom_ClientWorkUnitCoordinator::instance_mutex;

// Singleton access
FGCom_ClientWorkUnitCoordinator& FGCom_ClientWorkUnitCoordinator::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::make_unique<FGCom_ClientWorkUnitCoordinator>();
    }
    return *instance;
}

void FGCom_ClientWorkUnitCoordinator::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (instance) {
        instance->shutdown();
        instance.reset();
    }
}

// Constructor
FGCom_ClientWorkUnitCoordinator::FGCom_ClientWorkUnitCoordinator()
    : server_url("")
    , client_id("")
    , coordinator_enabled(false)
    , auto_request_work_units(true)
    , max_concurrent_work_units(2)
    , work_unit_request_interval_ms(5000)
    , heartbeat_interval_ms(30000)
    , workers_running(false)
    , coordinator_running(false) {
    
    // Initialize statistics
    total_work_units_received = 0;
    total_work_units_completed = 0;
    total_work_units_failed = 0;
    average_processing_time_ms = 0.0;
    average_queue_wait_time_ms = 0.0;
    
    // Initialize client capability
    client_capability.client_id = "";
    client_capability.max_memory_mb = 1024;
    client_capability.supports_gpu = false;
    client_capability.supports_double_precision = true;
    client_capability.network_bandwidth_mbps = 100.0;
    client_capability.processing_latency_ms = 100.0;
    client_capability.is_online = false;
    client_capability.active_units = 0;
    client_capability.pending_units = 0;
    client_capability.memory_usage_mb = 0;
    client_capability.cpu_utilization_percent = 0.0;
    client_capability.gpu_utilization_percent = 0.0;
}

// Initialization
bool FGCom_ClientWorkUnitCoordinator::initialize(const std::string& server_url, const std::string& client_id) {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    
    if (coordinator_enabled) {
        return true; // Already initialized
    }
    
    this->server_url = server_url;
    this->client_id = client_id;
    client_capability.client_id = client_id;
    client_capability.is_online = true;
    
    // Start worker threads
    workers_running = true;
    coordinator_running = true;
    
    int num_threads = std::min(max_concurrent_work_units, static_cast<int>(std::thread::hardware_concurrency()));
    for (int i = 0; i < num_threads; i++) {
        worker_threads.emplace_back(&FGCom_ClientWorkUnitCoordinator::workerThreadFunction, this);
    }
    
    // Start heartbeat thread
    heartbeat_thread = std::thread(&FGCom_ClientWorkUnitCoordinator::heartbeatThreadFunction, this);
    
    // Start work request thread if auto-requesting is enabled
    if (auto_request_work_units) {
        work_request_thread = std::thread(&FGCom_ClientWorkUnitCoordinator::workRequestThreadFunction, this);
    }
    
    coordinator_enabled = true;
    return true;
}

void FGCom_ClientWorkUnitCoordinator::shutdown() {
    if (!coordinator_enabled) {
        return;
    }
    
    // Stop all threads
    workers_running = false;
    coordinator_running = false;
    work_available.notify_all();
    
    // Wait for worker threads
    for (auto& thread : worker_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads.clear();
    
    // Wait for heartbeat thread
    if (heartbeat_thread.joinable()) {
        heartbeat_thread.join();
    }
    
    // Wait for work request thread
    if (work_request_thread.joinable()) {
        work_request_thread.join();
    }
    
    coordinator_enabled = false;
}

void FGCom_ClientWorkUnitCoordinator::setConfiguration(const std::map<std::string, std::string>& config) {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    
    auto it = config.find("max_concurrent_work_units");
    if (it != config.end()) {
        max_concurrent_work_units = std::stoi(it->second);
    }
    
    it = config.find("work_unit_request_interval_ms");
    if (it != config.end()) {
        work_unit_request_interval_ms = std::stoi(it->second);
    }
    
    it = config.find("heartbeat_interval_ms");
    if (it != config.end()) {
        heartbeat_interval_ms = std::stoi(it->second);
    }
    
    it = config.find("auto_request_work_units");
    if (it != config.end()) {
        auto_request_work_units = (it->second == "true" || it->second == "1");
    }
}

// Client capability management
void FGCom_ClientWorkUnitCoordinator::setClientCapability(const ClientWorkUnitCapability& capability) {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    client_capability = capability;
    client_capability.client_id = client_id;
    client_capability.is_online = true;
}

void FGCom_ClientWorkUnitCoordinator::updateCapability(const std::string& capability_type, const std::string& value) {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    
    if (capability_type == "max_memory_mb") {
        client_capability.max_memory_mb = std::stoi(value);
    } else if (capability_type == "supports_gpu") {
        client_capability.supports_gpu = (value == "true" || value == "1");
    } else if (capability_type == "network_bandwidth_mbps") {
        client_capability.network_bandwidth_mbps = std::stod(value);
    } else if (capability_type == "processing_latency_ms") {
        client_capability.processing_latency_ms = std::stod(value);
    }
}

ClientWorkUnitCapability FGCom_ClientWorkUnitCoordinator::getClientCapability() const {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    return client_capability;
}

// Work unit processing
bool FGCom_ClientWorkUnitCoordinator::enableAutoWorkUnitRequests(bool enable) {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    auto_request_work_units = enable;
    return true;
}

bool FGCom_ClientWorkUnitCoordinator::requestSpecificWorkUnitType(WorkUnitType type) {
    // This would make a specific request to the server for a particular work unit type
    // Implementation would depend on server API
    return true;
}

std::vector<std::string> FGCom_ClientWorkUnitCoordinator::getAssignedWorkUnits() {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    
    std::vector<std::string> assigned_units;
    for (const auto& pair : assigned_work_units) {
        assigned_units.push_back(pair.first);
    }
    
    return assigned_units;
}

std::vector<std::string> FGCom_ClientWorkUnitCoordinator::getProcessingWorkUnits() {
    std::lock_guard<std::mutex> lock(processing_mutex);
    
    std::vector<std::string> processing_units;
    for (const auto& pair : processing_futures) {
        processing_units.push_back(pair.first);
    }
    
    return processing_units;
}

WorkUnitStatus FGCom_ClientWorkUnitCoordinator::getWorkUnitStatus(const std::string& unit_id) {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    
    auto it = assigned_work_units.find(unit_id);
    if (it == assigned_work_units.end()) {
        return WorkUnitStatus::FAILED; // Unit not found
    }
    
    return it->second.status;
}

// Statistics and monitoring
std::map<std::string, double> FGCom_ClientWorkUnitCoordinator::getStatistics() {
    std::map<std::string, double> stats;
    
    stats["total_work_units_received"] = total_work_units_received.load();
    stats["total_work_units_completed"] = total_work_units_completed.load();
    stats["total_work_units_failed"] = total_work_units_failed.load();
    stats["average_processing_time_ms"] = average_processing_time_ms.load();
    stats["average_queue_wait_time_ms"] = average_queue_wait_time_ms.load();
    stats["assigned_work_units"] = assigned_work_units.size();
    stats["processing_work_units"] = processing_futures.size();
    
    return stats;
}

void FGCom_ClientWorkUnitCoordinator::resetStatistics() {
    total_work_units_received = 0;
    total_work_units_completed = 0;
    total_work_units_failed = 0;
    average_processing_time_ms = 0.0;
    average_queue_wait_time_ms = 0.0;
}

bool FGCom_ClientWorkUnitCoordinator::isHealthy() {
    return coordinator_enabled && workers_running && coordinator_running;
}

std::string FGCom_ClientWorkUnitCoordinator::getStatusReport() {
    std::stringstream ss;
    ss << "Client Work Unit Coordinator Status:\n";
    ss << "  Enabled: " << (coordinator_enabled ? "Yes" : "No") << "\n";
    ss << "  Workers Running: " << (workers_running ? "Yes" : "No") << "\n";
    ss << "  Coordinator Running: " << (coordinator_running ? "Yes" : "No") << "\n";
    ss << "  Auto Request Work Units: " << (auto_request_work_units ? "Yes" : "No") << "\n";
    ss << "  Max Concurrent Units: " << max_concurrent_work_units << "\n";
    ss << "  Assigned Work Units: " << assigned_work_units.size() << "\n";
    ss << "  Processing Work Units: " << processing_futures.size() << "\n";
    ss << "  Total Received: " << total_work_units_received.load() << "\n";
    ss << "  Total Completed: " << total_work_units_completed.load() << "\n";
    ss << "  Total Failed: " << total_work_units_failed.load() << "\n";
    
    return ss.str();
}

// Utility methods
void FGCom_ClientWorkUnitCoordinator::cleanup() {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    
    auto now = std::chrono::system_clock::now();
    auto cleanup_threshold = now - std::chrono::hours(1); // Keep units for 1 hour
    
    std::vector<std::string> units_to_remove;
    for (const auto& pair : assigned_work_units) {
        if (pair.second.completed_time < cleanup_threshold) {
            units_to_remove.push_back(pair.first);
        }
    }
    
    for (const std::string& unit_id : units_to_remove) {
        assigned_work_units.erase(unit_id);
    }
}

void FGCom_ClientWorkUnitCoordinator::forceCleanup() {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    
    // Remove all completed and failed units
    std::vector<std::string> units_to_remove;
    for (const auto& pair : assigned_work_units) {
        if (pair.second.status == WorkUnitStatus::COMPLETED || 
            pair.second.status == WorkUnitStatus::FAILED ||
            pair.second.status == WorkUnitStatus::TIMEOUT) {
            units_to_remove.push_back(pair.first);
        }
    }
    
    for (const std::string& unit_id : units_to_remove) {
        assigned_work_units.erase(unit_id);
    }
}

// Private methods
void FGCom_ClientWorkUnitCoordinator::workerThreadFunction() {
    while (workers_running) {
        std::unique_lock<std::mutex> lock(processing_mutex);
        
        // Wait for work or timeout
        work_available.wait_for(lock, std::chrono::milliseconds(1000));
        
        if (!workers_running) {
            break;
        }
        
        // Process available work units
        std::vector<std::string> units_to_process;
        {
            std::lock_guard<std::mutex> work_lock(work_units_mutex);
            
            for (const auto& pair : assigned_work_units) {
                if (pair.second.status == WorkUnitStatus::ASSIGNED && 
                    processing_futures.find(pair.first) == processing_futures.end()) {
                    units_to_process.push_back(pair.first);
                }
            }
        }
        
        // Process each unit
        for (const std::string& unit_id : units_to_process) {
            if (processing_futures.size() < max_concurrent_work_units) {
                processing_futures[unit_id] = std::async(std::launch::async, 
                    &FGCom_ClientWorkUnitCoordinator::processWorkUnit, this, unit_id);
            }
        }
        
        // Cleanup completed futures
        cleanupCompletedWorkUnits();
    }
}

void FGCom_ClientWorkUnitCoordinator::heartbeatThreadFunction() {
    while (coordinator_running) {
        // Send heartbeat to server
        // Implementation would depend on server API
        
        std::this_thread::sleep_for(std::chrono::milliseconds(heartbeat_interval_ms));
    }
}

void FGCom_ClientWorkUnitCoordinator::workRequestThreadFunction() {
    while (coordinator_running && auto_request_work_units) {
        // Request work units from server
        requestWorkUnitsFromServer();
        
        std::this_thread::sleep_for(std::chrono::milliseconds(work_unit_request_interval_ms));
    }
}

bool FGCom_ClientWorkUnitCoordinator::requestWorkUnitsFromServer() {
    // This would make HTTP requests to the server to request work units
    // Implementation would depend on server API
    return true;
}

bool FGCom_ClientWorkUnitCoordinator::submitWorkUnitResult(const std::string& unit_id, 
                                                          const std::vector<double>& result_data, 
                                                          bool success, 
                                                          const std::string& error_message) {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    
    auto it = assigned_work_units.find(unit_id);
    if (it == assigned_work_units.end()) {
        return false;
    }
    
    WorkUnit& unit = it->second;
    unit.result_data = result_data;
    unit.success = success;
    unit.error_message = error_message;
    unit.completed_time = std::chrono::system_clock::now();
    
    if (success) {
        unit.status = WorkUnitStatus::COMPLETED;
        total_work_units_completed++;
    } else {
        unit.status = WorkUnitStatus::FAILED;
        total_work_units_failed++;
    }
    
    return true;
}

void FGCom_ClientWorkUnitCoordinator::processWorkUnit(const std::string& unit_id) {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    
    auto it = assigned_work_units.find(unit_id);
    if (it == assigned_work_units.end()) {
        return;
    }
    
    WorkUnit& unit = it->second;
    unit.status = WorkUnitStatus::PROCESSING;
    unit.started_time = std::chrono::system_clock::now();
    
    // Execute the work unit
    std::vector<double> result = executeWorkUnit(unit);
    
    // Submit result
    submitWorkUnitResult(unit_id, result, true);
}

std::vector<double> FGCom_ClientWorkUnitCoordinator::executeWorkUnit(const WorkUnit& unit) {
    // Delegate to appropriate processor based on work unit type
    switch (unit.type) {
        case WorkUnitType::PROPAGATION_GRID:
            return FGCom_ClientWorkUnitProcessor::processPropagationGrid(
                unit.input_data, unit.parameters.at("frequency_mhz"), 
                unit.parameters.at("tx_power_watts"), unit.parameters);
            
        case WorkUnitType::ANTENNA_PATTERN:
            return FGCom_ClientWorkUnitProcessor::processAntennaPattern(
                unit.input_data, unit.parameters.at("frequency_mhz"), unit.parameters);
            
        case WorkUnitType::FREQUENCY_OFFSET:
            return FGCom_ClientWorkUnitProcessor::processFrequencyOffset(
                unit.input_data, unit.parameters.at("frequency_mhz"), unit.parameters);
            
        case WorkUnitType::AUDIO_PROCESSING:
            return FGCom_ClientWorkUnitProcessor::processAudio(unit.input_data, unit.parameters);
            
        case WorkUnitType::BATCH_QSO:
            return FGCom_ClientWorkUnitProcessor::processBatchQSO(
                std::vector<std::vector<double>>(), unit.parameters.at("frequency_mhz"), unit.parameters);
            
        case WorkUnitType::SOLAR_EFFECTS:
            return FGCom_ClientWorkUnitProcessor::processSolarEffects(
                unit.input_data, unit.parameters.at("frequency_mhz"), unit.parameters);
            
        case WorkUnitType::LIGHTNING_EFFECTS:
            return FGCom_ClientWorkUnitProcessor::processLightningEffects(
                unit.input_data, unit.parameters.at("frequency_mhz"), unit.parameters);
            
        default:
            return std::vector<double>();
    }
}

void FGCom_ClientWorkUnitCoordinator::updateClientCapabilities() {
    // Update client capabilities based on current system state
    // This would monitor CPU, memory, GPU usage, etc.
}

void FGCom_ClientWorkUnitCoordinator::handleWorkUnitTimeout(const std::string& unit_id) {
    std::lock_guard<std::mutex> lock(work_units_mutex);
    
    auto it = assigned_work_units.find(unit_id);
    if (it == assigned_work_units.end()) {
        return;
    }
    
    WorkUnit& unit = it->second;
    if (unit.status == WorkUnitStatus::PROCESSING) {
        unit.status = WorkUnitStatus::TIMEOUT;
        unit.error_message = "Processing timeout";
        total_work_units_failed++;
    }
}

void FGCom_ClientWorkUnitCoordinator::cleanupCompletedWorkUnits() {
    std::lock_guard<std::mutex> lock(processing_mutex);
    
    std::vector<std::string> completed_futures;
    for (auto& pair : processing_futures) {
        if (pair.second.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            completed_futures.push_back(pair.first);
        }
    }
    
    for (const std::string& unit_id : completed_futures) {
        processing_futures.erase(unit_id);
    }
}

// Client work unit processor implementations
std::vector<double> FGCom_ClientWorkUnitProcessor::processPropagationGrid(
    const std::vector<double>& grid_points,
    double frequency_mhz,
    double tx_power_watts,
    const std::map<std::string, double>& parameters) {
    
    // Implementation would use the existing propagation physics
    // This is a simplified placeholder
    std::vector<double> results;
    for (size_t i = 0; i < grid_points.size(); i += 2) {
        if (i + 1 < grid_points.size()) {
            double lat = grid_points[i];
            double lon = grid_points[i + 1];
            // Calculate propagation for this grid point
            double signal_strength = 1.0 / (1.0 + (lat * lat + lon * lon) / 1000.0);
            results.push_back(signal_strength);
        }
    }
    
    return results;
}

std::vector<double> FGCom_ClientWorkUnitProcessor::processAntennaPattern(
    const std::vector<double>& antenna_data,
    double frequency_mhz,
    const std::map<std::string, double>& parameters) {
    
    // Implementation would use the existing antenna pattern calculations
    // This is a simplified placeholder
    std::vector<double> results;
    for (double data : antenna_data) {
        results.push_back(data * frequency_mhz / 100.0);
    }
    
    return results;
}

std::vector<double> FGCom_ClientWorkUnitProcessor::processFrequencyOffset(
    const std::vector<double>& audio_data,
    double frequency_mhz,
    const std::map<std::string, double>& parameters) {
    
    // Implementation would process audio with frequency offset
    // This is a simplified placeholder
    std::vector<double> results;
    for (double sample : audio_data) {
        results.push_back(sample * (1.0 + frequency_mhz / 1000.0));
    }
    
    return results;
}

std::vector<double> FGCom_ClientWorkUnitProcessor::processAudio(
    const std::vector<double>& audio_data,
    const std::map<std::string, double>& parameters) {
    
    // Implementation would process audio data
    // This is a simplified placeholder
    return audio_data;
}

std::vector<double> FGCom_ClientWorkUnitProcessor::processBatchQSO(
    const std::vector<std::vector<double>>& qso_data,
    double frequency_mhz,
    const std::map<std::string, double>& parameters) {
    
    // Implementation would process batch QSO calculations
    // This is a simplified placeholder
    std::vector<double> results;
    for (const auto& qso : qso_data) {
        double result = 0.0;
        for (double value : qso) {
            result += value;
        }
        results.push_back(result);
    }
    
    return results;
}

std::vector<double> FGCom_ClientWorkUnitProcessor::processSolarEffects(
    const std::vector<double>& solar_data,
    double frequency_mhz,
    const std::map<std::string, double>& parameters) {
    
    // Implementation would process solar effects
    // This is a simplified placeholder
    std::vector<double> results;
    for (double data : solar_data) {
        results.push_back(data * (1.0 + frequency_mhz / 10000.0));
    }
    
    return results;
}

std::vector<double> FGCom_ClientWorkUnitProcessor::processLightningEffects(
    const std::vector<double>& lightning_data,
    double frequency_mhz,
    const std::map<std::string, double>& parameters) {
    
    // Implementation would process lightning effects
    // This is a simplified placeholder
    std::vector<double> results;
    for (double data : lightning_data) {
        results.push_back(data * (1.0 + frequency_mhz / 5000.0));
    }
    
    return results;
}

// Client-server communicator implementation
FGCom_ClientServerCommunicator::FGCom_ClientServerCommunicator(const std::string& server_url, const std::string& client_id)
    : server_url(server_url)
    , client_id(client_id)
    , connection_healthy(false)
    , connection_timeout_ms(5000) {
    
    last_heartbeat = std::chrono::system_clock::now();
}

bool FGCom_ClientServerCommunicator::registerClient(const ClientWorkUnitCapability& capability) {
    // Implementation would make HTTP POST request to server
    // This is a simplified placeholder
    return true;
}

bool FGCom_ClientServerCommunicator::unregisterClient() {
    // Implementation would make HTTP DELETE request to server
    // This is a simplified placeholder
    return true;
}

bool FGCom_ClientServerCommunicator::updateClientCapability(const ClientWorkUnitCapability& capability) {
    // Implementation would make HTTP PUT request to server
    // This is a simplified placeholder
    return true;
}

bool FGCom_ClientServerCommunicator::sendHeartbeat() {
    // Implementation would make HTTP GET request to server
    // This is a simplified placeholder
    last_heartbeat = std::chrono::system_clock::now();
    return true;
}

std::vector<WorkUnit> FGCom_ClientServerCommunicator::requestWorkUnits(int max_units) {
    // Implementation would make HTTP GET request to server
    // This is a simplified placeholder
    return std::vector<WorkUnit>();
}

bool FGCom_ClientServerCommunicator::submitWorkUnitResult(const std::string& unit_id, 
                                                         const std::vector<double>& result_data, 
                                                         bool success, 
                                                         const std::string& error_message) {
    // Implementation would make HTTP POST request to server
    // This is a simplified placeholder
    return true;
}

bool FGCom_ClientServerCommunicator::getServerStatus() {
    // Implementation would make HTTP GET request to server
    // This is a simplified placeholder
    return true;
}

std::map<std::string, double> FGCom_ClientServerCommunicator::getServerStatistics() {
    // Implementation would make HTTP GET request to server
    // This is a simplified placeholder
    return std::map<std::string, double>();
}

std::map<std::string, std::string> FGCom_ClientServerCommunicator::getServerConfiguration() {
    // Implementation would make HTTP GET request to server
    // This is a simplified placeholder
    return std::map<std::string, std::string>();
}

bool FGCom_ClientServerCommunicator::isConnected() {
    auto now = std::chrono::system_clock::now();
    auto time_since_heartbeat = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_heartbeat).count();
    return time_since_heartbeat < connection_timeout_ms;
}

void FGCom_ClientServerCommunicator::setConnectionTimeout(int timeout_ms) {
    connection_timeout_ms = timeout_ms;
}

std::string FGCom_ClientServerCommunicator::getLastError() {
    return last_error;
}

std::string FGCom_ClientServerCommunicator::makeHTTPRequest(const std::string& endpoint, const std::string& method, const std::string& data) {
    // Implementation would use libcurl or similar HTTP library
    // This is a simplified placeholder
    return "";
}

nlohmann::json FGCom_ClientServerCommunicator::parseJSONResponse(const std::string& response) {
    // Implementation would parse JSON response
    // This is a simplified placeholder
    return nlohmann::json();
}

bool FGCom_ClientServerCommunicator::handleHTTPError(int status_code, const std::string& response) {
    // Implementation would handle HTTP errors
    // This is a simplified placeholder
    return false;
}

// Work unit result aggregator implementation
bool FGCom_WorkUnitResultAggregator::addPartialResult(const std::string& work_unit_id, 
                                                     const std::string& client_id, 
                                                     const std::vector<double>& result_data) {
    std::lock_guard<std::mutex> lock(results_mutex);
    
    partial_results[work_unit_id] = result_data;
    contributing_clients[work_unit_id].push_back(client_id);
    
    return true;
}

std::vector<double> FGCom_WorkUnitResultAggregator::getAggregatedResult(const std::string& work_unit_id) {
    std::lock_guard<std::mutex> lock(results_mutex);
    
    auto it = partial_results.find(work_unit_id);
    if (it == partial_results.end()) {
        return std::vector<double>();
    }
    
    return it->second;
}

bool FGCom_WorkUnitResultAggregator::isResultComplete(const std::string& work_unit_id) {
    std::lock_guard<std::mutex> lock(results_mutex);
    
    auto it = contributing_clients.find(work_unit_id);
    if (it == contributing_clients.end()) {
        return false;
    }
    
    // Check if we have results from all expected clients
    // This would depend on the specific work unit requirements
    return it->second.size() >= 1; // Simplified check
}

std::vector<std::string> FGCom_WorkUnitResultAggregator::getContributingClients(const std::string& work_unit_id) {
    std::lock_guard<std::mutex> lock(results_mutex);
    
    auto it = contributing_clients.find(work_unit_id);
    if (it == contributing_clients.end()) {
        return std::vector<std::string>();
    }
    
    return it->second;
}

bool FGCom_WorkUnitResultAggregator::validateResult(const std::string& work_unit_id, const std::vector<double>& expected_result) {
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

double FGCom_WorkUnitResultAggregator::calculateResultConfidence(const std::string& work_unit_id) {
    std::lock_guard<std::mutex> lock(results_mutex);
    
    auto it = contributing_clients.find(work_unit_id);
    if (it == contributing_clients.end()) {
        return 0.0;
    }
    
    // Confidence based on number of contributing clients
    // More clients = higher confidence
    int client_count = it->second.size();
    return std::min(1.0, client_count / 3.0); // Max confidence with 3+ clients
}

void FGCom_WorkUnitResultAggregator::removeResult(const std::string& work_unit_id) {
    std::lock_guard<std::mutex> lock(results_mutex);
    
    partial_results.erase(work_unit_id);
    contributing_clients.erase(work_unit_id);
}

void FGCom_WorkUnitResultAggregator::cleanupOldResults(std::chrono::system_clock::time_point cutoff_time) {
    std::lock_guard<std::mutex> lock(results_mutex);
    
    // Implementation would remove old results
    // This is a simplified placeholder
}
