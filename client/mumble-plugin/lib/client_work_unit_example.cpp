/*
 * Client Work Unit Example
 * 
 * This file demonstrates how clients would use the work unit distribution system
 * to participate in distributed propagation calculations.
 */

#include "client_work_unit_coordinator.h"
#include <iostream>
#include <chrono>
#include <thread>

// Example client implementation
class ExampleClient {
private:
    FGCom_ClientWorkUnitCoordinator& coordinator;
    std::string server_url;
    std::string client_id;
    
public:
    ExampleClient(const std::string& server_url, const std::string& client_id)
        : coordinator(FGCom_ClientWorkUnitCoordinator::getInstance())
        , server_url(server_url)
        , client_id(client_id) {}
    
    bool initialize() {
        // Initialize the coordinator
        if (!coordinator.initialize(server_url, client_id)) {
            std::cerr << "Failed to initialize work unit coordinator" << std::endl;
            return false;
        }
        
        // Set client capabilities
        ClientWorkUnitCapability capability;
        capability.client_id = client_id;
        capability.supported_types = {
            WorkUnitType::PROPAGATION_GRID,
            WorkUnitType::ANTENNA_PATTERN,
            WorkUnitType::FREQUENCY_OFFSET,
            WorkUnitType::AUDIO_PROCESSING
        };
        capability.max_concurrent_units = {
            {WorkUnitType::PROPAGATION_GRID, 2},
            {WorkUnitType::ANTENNA_PATTERN, 1},
            {WorkUnitType::FREQUENCY_OFFSET, 3},
            {WorkUnitType::AUDIO_PROCESSING, 4}
        };
        capability.processing_speed_multiplier = {
            {WorkUnitType::PROPAGATION_GRID, 1.0},
            {WorkUnitType::ANTENNA_PATTERN, 0.8},
            {WorkUnitType::FREQUENCY_OFFSET, 1.2},
            {WorkUnitType::AUDIO_PROCESSING, 1.5}
        };
        capability.max_memory_mb = 2048;
        capability.supports_gpu = true;
        capability.supports_double_precision = true;
        capability.network_bandwidth_mbps = 100.0;
        capability.processing_latency_ms = 50.0;
        capability.is_online = true;
        
        coordinator.setClientCapability(capability);
        
        // Enable auto work unit requests
        coordinator.enableAutoWorkUnitRequests(true);
        
        std::cout << "Client initialized successfully" << std::endl;
        return true;
    }
    
    void run() {
        std::cout << "Client running - participating in distributed processing" << std::endl;
        
        // Monitor work unit processing
        while (true) {
            // Get current status
            auto stats = coordinator.getStatistics();
            auto assigned_units = coordinator.getAssignedWorkUnits();
            auto processing_units = coordinator.getProcessingWorkUnits();
            
            std::cout << "Status: " << assigned_units.size() << " assigned, " 
                      << processing_units.size() << " processing" << std::endl;
            
            // Print statistics
            for (const auto& stat : stats) {
                std::cout << "  " << stat.first << ": " << stat.second << std::endl;
            }
            
            // Sleep for a bit
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }
    
    void shutdown() {
        coordinator.shutdown();
        std::cout << "Client shutdown complete" << std::endl;
    }
};

// Example usage
int main() {
    std::cout << "FGCom Work Unit Distribution Client Example" << std::endl;
    
    // Create client
    ExampleClient client("http://localhost:8080", "client_001");
    
    // Initialize
    if (!client.initialize()) {
        std::cerr << "Failed to initialize client" << std::endl;
        return 1;
    }
    
    // Run client
    try {
        client.run();
    } catch (const std::exception& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
    }
    
    // Shutdown
    client.shutdown();
    
    return 0;
}

// Example of how the system works:
/*
 * 1. Client connects to server and registers capabilities
 * 2. Server distributes work units based on client capabilities
 * 3. Client processes work units using local GPU/CPU resources
 * 4. Client submits results back to server
 * 5. Server aggregates results from multiple clients
 * 6. Server distributes final results to all clients
 * 
 * This allows for:
 * - Distributed propagation calculations
 * - Load balancing across multiple clients
 * - GPU acceleration on client machines
 * - Scalable processing for large simulations
 */
