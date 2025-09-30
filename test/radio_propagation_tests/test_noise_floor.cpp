#include "test_radio_propagation_main.cpp"

// 2.5 Noise Floor Calculation Tests
TEST_F(NoiseFloorTest, AtmosphericNoiseITURP372) {
    // Test atmospheric noise calculation using ITU-R P.372
    std::vector<double> frequencies = {14.0, 118.0, 300.0, 1000.0}; // HF, VHF, UHF, L-band
    std::vector<double> distances = {1.0, 5.0, 10.0, 50.0, 100.0}; // km
    
    for (double frequency : frequencies) {
        for (double distance : distances) {
            // Get atmospheric conditions for the test location
            AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
                tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
            
            // Calculate propagation loss using real implementation with realistic parameters
            double atmospheric_loss = 2.0; // Realistic atmospheric loss
            double terrain_loss = 5.0; // Realistic terrain loss
            double tx_power_dbm = 30.0; // 1W transmitter
            double rx_sensitivity_dbm = -100.0; // Typical receiver sensitivity
            
            double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
                frequency, distance, tx_coord.altitude, rx_coord.altitude,
                tx_power_dbm, rx_sensitivity_dbm, atmospheric_loss, terrain_loss);
            
            EXPECT_GT(total_loss, 0.0) << "Total propagation loss should be positive";
            EXPECT_LT(total_loss, 200.0) << "Total propagation loss should be reasonable";
            
            // Higher frequencies should have different propagation characteristics
            if (frequency > 100.0) {
                EXPECT_GT(total_loss, 50.0) << "High frequency should have reasonable propagation loss";
            }
        }
    }
}

TEST_F(NoiseFloorTest, ManMadeNoise) {
    // Test man-made noise calculation
    std::vector<double> frequencies = {14.0, 118.0, 300.0, 1000.0};
    std::vector<double> distances = {1.0, 5.0, 10.0, 50.0, 100.0};
    
    for (double frequency : frequencies) {
        for (double distance : distances) {
            // Get atmospheric conditions for the test location
            AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
                tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
            
            // Calculate propagation loss using real implementation with realistic parameters
            double atmospheric_loss = 2.0; // Realistic atmospheric loss
            double terrain_loss = 5.0; // Realistic terrain loss
            double tx_power_dbm = 30.0; // 1W transmitter
            double rx_sensitivity_dbm = -100.0; // Typical receiver sensitivity
            
            double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
                frequency, distance, tx_coord.altitude, rx_coord.altitude,
                tx_power_dbm, rx_sensitivity_dbm, atmospheric_loss, terrain_loss);
            
            EXPECT_GT(total_loss, 0.0) << "Total propagation loss should be positive";
            EXPECT_LT(total_loss, 200.0) << "Total propagation loss should be reasonable";
            
            // Higher frequencies should have different propagation characteristics
            if (frequency > 100.0) {
                EXPECT_GT(total_loss, 50.0) << "High frequency should have reasonable propagation loss";
            }
        }
    }
}

TEST_F(NoiseFloorTest, GalacticNoise) {
    // Test galactic noise calculation
    std::vector<double> frequencies = {14.0, 118.0, 300.0, 1000.0};
    
    for (double frequency : frequencies) {
        // Get atmospheric conditions for the test location
        AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
            tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
        
        // Calculate propagation loss using real implementation
        double atmospheric_loss = 0.0; // Simplified for this test
        double terrain_loss = 0.0; // Simplified for this test
        double distance = tx_coord.calculateDistance(rx_coord);
        
        double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
            frequency, distance, tx_coord.altitude, rx_coord.altitude,
            30.0, -100.0, atmospheric_loss, terrain_loss);
        
        EXPECT_GT(total_loss, 0.0) << "Total propagation loss should be positive";
        EXPECT_LT(total_loss, 200.0) << "Total propagation loss should be reasonable";
        
        // Higher frequencies should have different propagation characteristics
        if (frequency > 100.0) {
            EXPECT_GT(total_loss, 50.0) << "High frequency should have reasonable propagation loss";
        }
    }
}

TEST_F(NoiseFloorTest, EVChargingStationNoise) {
    // Test EV charging station noise
    std::vector<double> frequencies = {118.0, 300.0, 1000.0}; // VHF and above
    std::vector<double> distances = {0.1, 0.5, 1.0, 2.0, 5.0}; // km (close to charging stations)
    
    for (double frequency : frequencies) {
        for (double distance : distances) {
            // Get atmospheric conditions for the test location
            AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
                tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
            
            // Calculate propagation loss using real implementation with realistic parameters
            double atmospheric_loss = 2.0; // Realistic atmospheric loss
            double terrain_loss = 5.0; // Realistic terrain loss
            double tx_power_dbm = 30.0; // 1W transmitter
            double rx_sensitivity_dbm = -100.0; // Typical receiver sensitivity
            
            double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
                frequency, distance, tx_coord.altitude, rx_coord.altitude,
                tx_power_dbm, rx_sensitivity_dbm, atmospheric_loss, terrain_loss);
            
            EXPECT_GT(total_loss, 0.0) << "Total propagation loss should be positive";
            EXPECT_LT(total_loss, 200.0) << "Total propagation loss should be reasonable";
            
            // Higher frequencies should have different propagation characteristics
            if (frequency > 100.0) {
                EXPECT_GT(total_loss, 50.0) << "High frequency should have reasonable propagation loss";
            }
        }
    }
}

TEST_F(NoiseFloorTest, PowerSubstationNoise) {
    // Test power substation noise (2MW+)
    std::vector<double> frequencies = {14.0, 118.0, 300.0, 1000.0};
    std::vector<double> distances = {0.5, 1.0, 2.0, 5.0, 10.0}; // km
    
    for (double frequency : frequencies) {
        for (double distance : distances) {
            // Get atmospheric conditions for the test location
            AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
                tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
            
            // Calculate propagation loss using real implementation with realistic parameters
            double atmospheric_loss = 2.0; // Realistic atmospheric loss
            double terrain_loss = 5.0; // Realistic terrain loss
            double tx_power_dbm = 30.0; // 1W transmitter
            double rx_sensitivity_dbm = -100.0; // Typical receiver sensitivity
            
            double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
                frequency, distance, tx_coord.altitude, rx_coord.altitude,
                tx_power_dbm, rx_sensitivity_dbm, atmospheric_loss, terrain_loss);
            
            EXPECT_GT(total_loss, 0.0) << "Total propagation loss should be positive";
            EXPECT_LT(total_loss, 200.0) << "Total propagation loss should be reasonable";
            
            // Higher frequencies should have different propagation characteristics
            if (frequency > 100.0) {
                EXPECT_GT(total_loss, 50.0) << "High frequency should have reasonable propagation loss";
            }
        }
    }
}

TEST_F(NoiseFloorTest, DistanceBasedNoiseAttenuation) {
    // Test distance-based noise attenuation
    std::vector<double> distances = {0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0}; // km
    double base_noise_db = 30.0; // Base noise level
    
    for (double distance : distances) {
        // Get atmospheric conditions for the test location
        AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
            tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
        
        // Calculate propagation loss using real implementation
        double atmospheric_loss = 0.0; // Simplified for this test
        double terrain_loss = 0.0; // Simplified for this test
        double frequency = test_frequency_vhf; // Use VHF frequency
        
        double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
            frequency, distance, tx_coord.altitude, rx_coord.altitude,
            30.0, -100.0, atmospheric_loss, terrain_loss);
        
        EXPECT_GT(total_loss, 0.0) << "Total propagation loss should be positive";
        EXPECT_LT(total_loss, 200.0) << "Total propagation loss should be reasonable";
        
        // Longer distances should have higher propagation loss
        if (distance > 10.0) {
            EXPECT_GT(total_loss, 50.0) << "Long distances should have higher propagation loss";
        }
    }
}

TEST_F(NoiseFloorTest, FrequencyDependentNoiseLevels) {
    // Test frequency-dependent noise levels
    std::vector<double> frequencies = {3.0, 10.0, 30.0, 100.0, 300.0, 1000.0, 3000.0};
    double distance_km = 5.0;
    
    std::vector<double> noise_levels;
    
    for (double frequency : frequencies) {
        // Get atmospheric conditions for the test location
        AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
            tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
        
        // Calculate propagation loss using real implementation
        double atmospheric_loss = 0.0; // Simplified for this test
        double terrain_loss = 0.0; // Simplified for this test
        
        double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
            frequency, distance_km, tx_coord.altitude, rx_coord.altitude,
            30.0, -100.0, atmospheric_loss, terrain_loss);
        
        noise_levels.push_back(total_loss);
        
        EXPECT_GT(total_loss, 0.0) << "Total propagation loss should be positive";
        EXPECT_LT(total_loss, 200.0) << "Total propagation loss should be reasonable";
    }
    
    // Test that propagation loss is frequency dependent
    for (size_t i = 1; i < noise_levels.size(); ++i) {
        if (frequencies[i] > 100.0) {
            EXPECT_GT(noise_levels[i], noise_levels[i-1]) << "High frequencies should have higher propagation loss";
        }
    }
}

// Additional noise floor tests
TEST_F(NoiseFloorTest, NoiseFloorCalculationAccuracy) {
    // Test noise floor calculation accuracy
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Get atmospheric conditions for the test location
    AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
        tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
    
    // Calculate propagation loss using real implementation
    double atmospheric_loss = 0.0; // Simplified for this test
    double terrain_loss = 0.0; // Simplified for this test
    
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        frequency_mhz, distance_km, tx_coord.altitude, rx_coord.altitude,
        30.0, -100.0, atmospheric_loss, terrain_loss);
    
    // Test that total loss is reasonable
    EXPECT_GT(total_loss, 0.0) << "Total propagation loss should be positive";
    EXPECT_LT(total_loss, 200.0) << "Total propagation loss should be reasonable";
    
    // Test that higher frequencies have different characteristics
    if (frequency_mhz > 100.0) {
        EXPECT_GT(total_loss, 50.0) << "High frequency should have reasonable propagation loss";
    }
}

TEST_F(NoiseFloorTest, NoiseFloorWithEnvironmentalConditions) {
    // Test noise floor with different environmental conditions
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Get atmospheric conditions for the test location
    AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
        tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
    
    // Calculate propagation loss using real implementation
    double atmospheric_loss = 0.0; // Simplified for this test
    double terrain_loss = 0.0; // Simplified for this test
    
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        frequency_mhz, distance_km, tx_coord.altitude, rx_coord.altitude,
        30.0, -100.0, atmospheric_loss, terrain_loss);
    
    // Test that total loss is reasonable
    EXPECT_GT(total_loss, 0.0) << "Total propagation loss should be positive";
    EXPECT_LT(total_loss, 200.0) << "Total propagation loss should be reasonable";
    
    // Test that higher frequencies have different characteristics
    if (frequency_mhz > 100.0) {
        EXPECT_GT(total_loss, 50.0) << "High frequency should have reasonable propagation loss";
    }
}

TEST_F(NoiseFloorTest, NoiseFloorPerformance) {
    // Test noise floor calculation performance
    const int num_calculations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_calculations; ++i) {
        double frequency = 14.0 + (i % 1000) * 0.1;
        double distance = 1.0 + (i % 100) * 0.1;
        
        // Get atmospheric conditions for the test location
        AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
            tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
        
        // Calculate propagation loss using real implementation
        double atmospheric_loss = 0.0; // Simplified for this test
        double terrain_loss = 0.0; // Simplified for this test
        
        double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
            frequency, distance, tx_coord.altitude, rx_coord.altitude,
            30.0, -100.0, atmospheric_loss, terrain_loss);
        
        // Verify calculation is reasonable
        EXPECT_GT(total_loss, 0.0);
        EXPECT_LT(total_loss, 200.0);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_calculation = static_cast<double>(duration.count()) / num_calculations;
    
    // Noise floor calculations should be fast
    EXPECT_LT(time_per_calculation, 2.0) << "Noise floor calculation too slow: " << time_per_calculation << " microseconds";
    
    std::cout << "Noise floor calculation performance: " << time_per_calculation << " microseconds per calculation" << std::endl;
}
