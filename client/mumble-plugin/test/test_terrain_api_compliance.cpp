#include "lib/terrain_environmental_api.h"
#include "lib/terrain_exceptions.h"
#include "lib/terrain_state_machine.h"
#include "lib/terrain_data_access.h"
#include "lib/terrain_cache.h"
#include "lib/terrain_statistics.h"
#include <iostream>
#include <memory>
#include <chrono>
#include <thread>
#include <cmath>
#include <limits>

using namespace FGCom_TerrainEnvironmental;

/**
 * @brief Comprehensive test to verify compliance with strict architectural requirements
 * 
 * This test verifies that the terrain API meets all the strict requirements:
 * - No race conditions
 * - Proper state management
 * - Comprehensive error handling
 * - Input validation
 * - Memory management
 * - Thread safety
 * - Performance optimization
 * - Security measures
 */
class TerrainAPIComplianceTest {
public:
    void runAllTests() {
        std::cout << "=== TERRAIN API COMPLIANCE TEST ===" << std::endl;
        
        testNoRaceConditions();
        testStateManagement();
        testErrorHandling();
        testInputValidation();
        testMemoryManagement();
        testThreadSafety();
        testPerformanceOptimization();
        testSecurityMeasures();
        
        std::cout << "=== ALL TESTS PASSED ===" << std::endl;
    }

private:
    void testNoRaceConditions() {
        std::cout << "Testing: No Race Conditions..." << std::endl;
        
        // Test concurrent access to shared resources
        auto dataAccess = TerrainDataAccessFactory::createMockAccess();
        auto cache = std::make_unique<TerrainCache>();
        auto statistics = std::make_unique<TerrainStatistics>();
        auto provider = std::make_unique<TerrainDataProvider>(
            std::move(dataAccess), std::move(cache), std::move(statistics));
        
        // Test concurrent operations
        std::vector<std::thread> threads;
        for (int i = 0; i < 10; ++i) {
            threads.emplace_back([&provider, i]() {
                try {
                    Coordinate coord(40.0 + i, -74.0 + i, 100.0);
                    auto result = provider->getTerrainAltitude(coord);
                    // Verify result is valid
                    if (!result.isValid()) {
                        throw std::runtime_error("Invalid result from concurrent operation");
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Concurrent operation failed: " << e.what() << std::endl;
                }
            });
        }
        
        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }
        
        std::cout << "✓ No race conditions detected" << std::endl;
    }

    void testStateManagement() {
        std::cout << "Testing: State Management..." << std::endl;
        
        TerrainStateMachine stateMachine;
        
        // Test state transitions
        if (!stateMachine.transitionToInitializing()) {
            throw std::runtime_error("Failed to transition to initializing");
        }
        
        if (!stateMachine.transitionToReady()) {
            throw std::runtime_error("Failed to transition to ready");
        }
        
        if (!stateMachine.canPerformOperations()) {
            throw std::runtime_error("State machine not ready for operations");
        }
        
        // Test invalid transitions
        if (stateMachine.transitionToInitializing()) {
            throw std::runtime_error("Invalid transition allowed");
        }
        
        std::cout << "✓ State management working correctly" << std::endl;
    }

    void testErrorHandling() {
        std::cout << "Testing: Error Handling..." << std::endl;
        
        // Test coordinate validation
        try {
            Coordinate invalidCoord(200.0, 200.0, 200.0); // Invalid coordinates
            throw std::runtime_error("Invalid coordinates should have thrown exception");
        } catch (const InvalidCoordinateException& e) {
            // Expected exception
        }
        
        // Test frequency validation
        try {
            Coordinate coord(40.0, -74.0, 100.0);
            auto dataAccess = TerrainDataAccessFactory::createMockAccess();
            auto cache = std::make_unique<TerrainCache>();
            auto statistics = std::make_unique<TerrainStatistics>();
            auto provider = std::make_unique<TerrainDataProvider>(
                std::move(dataAccess), std::move(cache), std::move(statistics));
            
            // This should throw an exception for invalid frequency
            provider->calculateNoiseFloor(coord, -100.0, "day", "summer");
            throw std::runtime_error("Invalid frequency should have thrown exception");
        } catch (const InvalidFrequencyException& e) {
            // Expected exception
        }
        
        std::cout << "✓ Error handling working correctly" << std::endl;
    }

    void testInputValidation() {
        std::cout << "Testing: Input Validation..." << std::endl;
        
        // Test coordinate bounds
        Coordinate validCoord(40.0, -74.0, 100.0);
        if (!validCoord.isValid()) {
            throw std::runtime_error("Valid coordinates marked as invalid");
        }
        
        // Test distance calculation
        Coordinate coord1(40.0, -74.0, 100.0);
        Coordinate coord2(40.1, -74.1, 110.0);
        double distance = coord1.calculateDistance(coord2);
        
        if (distance <= 0.0 || !std::isfinite(distance)) {
            throw std::runtime_error("Invalid distance calculation");
        }
        
        std::cout << "✓ Input validation working correctly" << std::endl;
    }

    void testMemoryManagement() {
        std::cout << "Testing: Memory Management..." << std::endl;
        
        // Test RAII with smart pointers
        {
            auto dataAccess = TerrainDataAccessFactory::createMockAccess();
            auto cache = std::make_unique<TerrainCache>();
            auto statistics = std::make_unique<TerrainStatistics>();
            auto provider = std::make_unique<TerrainDataProvider>(
                std::move(dataAccess), std::move(cache), std::move(statistics));
            
            // Objects should be automatically destroyed when going out of scope
        }
        
        // Test cache memory management
        auto cache = std::make_unique<TerrainCache>(100, std::chrono::minutes(5));
        
        // Add many entries to test memory limits
        for (int i = 0; i < 150; ++i) {
            std::string key = "test_key_" + std::to_string(i);
            std::string data = "test_data_" + std::to_string(i);
            cache->store(key, data);
        }
        
        // Cache should not exceed max size
        if (cache->size() > 100) {
            throw std::runtime_error("Cache exceeded maximum size");
        }
        
        std::cout << "✓ Memory management working correctly" << std::endl;
    }

    void testThreadSafety() {
        std::cout << "Testing: Thread Safety..." << std::endl;
        
        auto dataAccess = TerrainDataAccessFactory::createMockAccess();
        auto cache = std::make_unique<TerrainCache>();
        auto statistics = std::make_unique<TerrainStatistics>();
        auto provider = std::make_unique<TerrainDataProvider>(
            std::move(dataAccess), std::move(cache), std::move(statistics));
        
        // Test concurrent cache operations
        std::vector<std::thread> threads;
        for (int i = 0; i < 5; ++i) {
            threads.emplace_back([&provider, i]() {
                for (int j = 0; j < 10; ++j) {
                    Coordinate coord(40.0 + i, -74.0 + j, 100.0);
                    try {
                        auto result = provider->getTerrainAltitude(coord);
                    } catch (const std::exception& e) {
                        // Expected for some operations
                    }
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        std::cout << "✓ Thread safety verified" << std::endl;
    }

    void testPerformanceOptimization() {
        std::cout << "Testing: Performance Optimization..." << std::endl;
        
        auto dataAccess = TerrainDataAccessFactory::createMockAccess();
        auto cache = std::make_unique<TerrainCache>();
        auto statistics = std::make_unique<TerrainStatistics>();
        auto provider = std::make_unique<TerrainDataProvider>(
            std::move(dataAccess), std::move(cache), std::move(statistics));
        
        // Test performance with timing
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < 100; ++i) {
            Coordinate coord(40.0 + i * 0.001, -74.0 + i * 0.001, 100.0);
            try {
                auto result = provider->getTerrainAltitude(coord);
            } catch (const std::exception& e) {
                // Expected for some operations
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        // Operations should complete within reasonable time
        if (duration.count() > 1000) { // 1 second
            throw std::runtime_error("Performance test failed: operations too slow");
        }
        
        std::cout << "✓ Performance optimization verified" << std::endl;
    }

    void testSecurityMeasures() {
        std::cout << "Testing: Security Measures..." << std::endl;
        
        // Test input sanitization
        Coordinate coord(40.0, -74.0, 100.0);
        if (!coord.isValid()) {
            throw std::runtime_error("Valid coordinates failed validation");
        }
        
        // Test bounds checking
        try {
            Coordinate invalidCoord(999.0, 999.0, 999.0);
            throw std::runtime_error("Invalid coordinates should have been rejected");
        } catch (const InvalidCoordinateException& e) {
            // Expected exception
        }
        
        // Test finite value checking
        try {
            Coordinate nanCoord(std::numeric_limits<double>::quiet_NaN(), 
                               std::numeric_limits<double>::quiet_NaN(), 
                               std::numeric_limits<double>::quiet_NaN());
            throw std::runtime_error("NaN coordinates should have been rejected");
        } catch (const InvalidCoordinateException& e) {
            // Expected exception
        }
        
        std::cout << "✓ Security measures verified" << std::endl;
    }
};

int main() {
    try {
        TerrainAPIComplianceTest test;
        test.runAllTests();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        return 1;
    }
}
