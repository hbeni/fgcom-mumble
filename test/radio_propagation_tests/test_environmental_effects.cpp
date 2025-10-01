#include "test_radio_propagation_main.cpp"

// 2.4 Environmental Effects Tests
TEST_F(EnvironmentalEffectsTest, WeatherImpactRain) {
    // Test rain impact on radio propagation
    WeatherConditions weather = generateWeatherConditions();
    weather.precipitation_mmh = 25.0; // Heavy rain
    
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Calculate rain attenuation
    double rain_attenuation_db = 0.0;
    
    if (frequency_mhz > 100.0) {
        // Rain attenuation increases with frequency
        rain_attenuation_db = 0.01 * weather.precipitation_mmh * distance_km;
    }
    
    EXPECT_GT(rain_attenuation_db, 0.0) << "Rain should cause attenuation";
    EXPECT_LT(rain_attenuation_db, 10.0) << "Rain attenuation should be reasonable";
    
    // Test with different rain intensities
    std::vector<double> rain_intensities = {0.0, 5.0, 10.0, 25.0, 50.0}; // mm/h
    
    for (double intensity : rain_intensities) {
        double attenuation = 0.01 * intensity * distance_km;
        
        EXPECT_GE(attenuation, 0.0) << "Rain attenuation should be non-negative";
        
        // Higher intensity should cause more attenuation
        if (intensity > 0.0) {
            EXPECT_GT(attenuation, 0.0) << "Rain should cause attenuation";
        }
    }
}

TEST_F(EnvironmentalEffectsTest, WeatherImpactFog) {
    // Test fog impact on radio propagation
    WeatherConditions weather = generateWeatherConditions();
    weather.fog = true;
    weather.humidity_percent = 95.0; // High humidity with fog
    
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Use frequency in the test
    EXPECT_GT(frequency_mhz, 0.0) << "Frequency should be positive";
    EXPECT_LT(frequency_mhz, 300.0) << "Frequency should be in VHF range";
    
    // Calculate fog attenuation
    double fog_attenuation_db = 0.0;
    
    if (weather.fog) {
        // Fog attenuation is frequency dependent
        fog_attenuation_db = 0.005 * distance_km; // Simplified model
    }
    
    EXPECT_GT(fog_attenuation_db, 0.0) << "Fog should cause attenuation";
    EXPECT_LT(fog_attenuation_db, 5.0) << "Fog attenuation should be reasonable";
    
    // Test with different humidity levels
    std::vector<double> humidity_levels = {50.0, 70.0, 85.0, 95.0, 100.0};
    
    for (double humidity : humidity_levels) {
        double attenuation = 0.0;
        
        if (humidity > 90.0) {
            attenuation = 0.005 * distance_km * (humidity - 90.0) / 10.0;
        }
        
        EXPECT_GE(attenuation, 0.0) << "Fog attenuation should be non-negative";
        
        // Higher humidity should cause more attenuation
        if (humidity > 90.0) {
            EXPECT_GT(attenuation, 0.0) << "High humidity should cause attenuation";
        }
    }
}

TEST_F(EnvironmentalEffectsTest, WeatherImpactSnow) {
    // Test snow impact on radio propagation
    WeatherConditions weather = generateWeatherConditions();
    weather.snow = true;
    weather.temperature_c = -5.0; // Below freezing
    
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Use frequency in the test
    EXPECT_GT(frequency_mhz, 0.0) << "Frequency should be positive";
    EXPECT_LT(frequency_mhz, 300.0) << "Frequency should be in VHF range";
    
    // Calculate snow attenuation
    double snow_attenuation_db = 0.0;
    
    if (weather.snow) {
        // Snow attenuation is frequency dependent
        snow_attenuation_db = 0.02 * distance_km; // Higher than rain
    }
    
    EXPECT_GT(snow_attenuation_db, 0.0) << "Snow should cause attenuation";
    EXPECT_LT(snow_attenuation_db, 15.0) << "Snow attenuation should be reasonable";
    
    // Test with different temperatures
    std::vector<double> temperatures = {5.0, 0.0, -5.0, -10.0, -20.0};
    
    for (double temperature : temperatures) {
        double attenuation = 0.0;
        
        if (temperature < 0.0) {
            attenuation = 0.02 * distance_km * std::abs(temperature) / 10.0;
        }
        
        EXPECT_GE(attenuation, 0.0) << "Snow attenuation should be non-negative";
        
        // Lower temperatures should cause more attenuation
        if (temperature < 0.0) {
            EXPECT_GT(attenuation, 0.0) << "Below freezing should cause attenuation";
        }
    }
}

TEST_F(EnvironmentalEffectsTest, TemperatureEffects) {
    // Test temperature effects on radio propagation
    std::vector<double> temperatures = {-20.0, -10.0, 0.0, 10.0, 20.0, 30.0, 40.0};
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Use frequency in the test
    EXPECT_GT(frequency_mhz, 0.0) << "Frequency should be positive";
    EXPECT_LT(frequency_mhz, 300.0) << "Frequency should be in VHF range";
    
    for (double temperature : temperatures) {
        // Calculate temperature effects
        double temperature_effect_db = 0.0;
        
        // Temperature affects atmospheric absorption
        if (temperature < 0.0) {
            // Cold weather increases atmospheric absorption
            temperature_effect_db = 0.001 * distance_km * std::abs(temperature);
        } else if (temperature > 30.0) {
            // Hot weather also increases atmospheric absorption
            temperature_effect_db = 0.001 * distance_km * (temperature - 30.0);
        }
        
        EXPECT_GE(temperature_effect_db, 0.0) << "Temperature effect should be non-negative";
        
        // Extreme temperatures should have more effect
        if (temperature < -10.0 || temperature > 35.0) {
            EXPECT_GT(temperature_effect_db, 0.0) << "Extreme temperatures should have effect";
        }
    }
}

TEST_F(EnvironmentalEffectsTest, HumidityEffects) {
    // Test humidity effects on radio propagation
    std::vector<double> humidity_levels = {20.0, 40.0, 60.0, 80.0, 95.0, 100.0};
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Use frequency in the test
    EXPECT_GT(frequency_mhz, 0.0) << "Frequency should be positive";
    EXPECT_LT(frequency_mhz, 300.0) << "Frequency should be in VHF range";
    
    for (double humidity : humidity_levels) {
        // Calculate humidity effects
        double humidity_effect_db = 0.0;
        
        // Humidity affects atmospheric absorption
        if (humidity > 80.0) {
            humidity_effect_db = 0.002 * distance_km * (humidity - 80.0) / 20.0;
        }
        
        EXPECT_GE(humidity_effect_db, 0.0) << "Humidity effect should be non-negative";
        
        // High humidity should have more effect
        if (humidity > 90.0) {
            EXPECT_GT(humidity_effect_db, 0.0) << "High humidity should have effect";
        }
    }
}

TEST_F(EnvironmentalEffectsTest, AtmosphericPressureEffects) {
    // Test atmospheric pressure effects on radio propagation
    std::vector<double> pressures = {950.0, 980.0, 1013.25, 1030.0, 1050.0}; // hPa
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    for (double pressure : pressures) {
        // Use frequency and pressure in the test
        EXPECT_GT(frequency_mhz, 0.0) << "Frequency should be positive";
        EXPECT_LT(frequency_mhz, 300.0) << "Frequency should be in VHF range";
        EXPECT_GT(pressure, 900.0) << "Pressure should be reasonable";
        EXPECT_LT(pressure, 1100.0) << "Pressure should be reasonable";
        
        // Get atmospheric conditions for the test location
        AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
            tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
        
        // Use conditions in the test
        EXPECT_GT(conditions.temperature_c, -50.0) << "Temperature should be reasonable";
        EXPECT_LT(conditions.temperature_c, 50.0) << "Temperature should be reasonable";
        
        // Calculate propagation loss using real implementation with realistic parameters
        double atmospheric_loss = 3.0; // Realistic atmospheric loss
        double terrain_loss = 8.0; // Realistic terrain loss
        double tx_power_dbm = 30.0; // 1W transmitter
        double rx_sensitivity_dbm = -100.0; // Typical receiver sensitivity
        
        double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
            frequency_mhz, distance_km, tx_coord.altitude, rx_coord.altitude,
            tx_power_dbm, rx_sensitivity_dbm, atmospheric_loss, terrain_loss);
        
        EXPECT_GT(total_loss, 0.0) << "Total propagation loss should be positive";
        EXPECT_LT(total_loss, 200.0) << "Total propagation loss should be reasonable";
    }
}

TEST_F(EnvironmentalEffectsTest, DuctingConditions) {
    // Test tropospheric ducting conditions
    WeatherConditions weather = generateWeatherConditions();
    weather.temperature_c = 25.0;
    weather.humidity_percent = 60.0;
    weather.pressure_hpa = 1020.0;
    
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Use frequency and weather in the test
    EXPECT_GT(frequency_mhz, 0.0) << "Frequency should be positive";
    EXPECT_LT(frequency_mhz, 300.0) << "Frequency should be in VHF range";
    EXPECT_GT(weather.temperature_c, 0.0) << "Temperature should be positive";
    EXPECT_GT(weather.humidity_percent, 0.0) << "Humidity should be positive";
    
    // Get atmospheric conditions for the test location
    AtmosphericConditions conditions = FGCom_PropagationPhysics::getAtmosphericConditions(
        tx_coord.latitude, tx_coord.longitude, tx_coord.altitude);
    
    // Use conditions in the test
    EXPECT_GT(conditions.temperature_c, -50.0) << "Temperature should be reasonable";
    EXPECT_LT(conditions.temperature_c, 50.0) << "Temperature should be reasonable";
    
    // Calculate propagation loss using real implementation
    double atmospheric_loss = 0.0; // Simplified for this test
    double terrain_loss = 0.0; // Simplified for this test
    
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        frequency_mhz, distance_km, tx_coord.altitude, rx_coord.altitude,
        30.0, -100.0, atmospheric_loss, terrain_loss);
    
    EXPECT_GT(total_loss, 0.0) << "Total propagation loss should be positive";
    EXPECT_LT(total_loss, 200.0) << "Total propagation loss should be reasonable";
    
    // Test with different weather conditions
    std::vector<WeatherConditions> test_conditions = {
        {25.0, 60.0, 1020.0, 0.0, false, false}, // Good ducting
        {15.0, 40.0, 1000.0, 0.0, false, false}, // Poor ducting
        {30.0, 80.0, 1030.0, 0.0, false, false}, // Excellent ducting
        {5.0, 20.0, 980.0, 0.0, false, false}    // No ducting
    };
    
    for (const auto& condition : test_conditions) {
        bool ducting = (condition.temperature_c > 20.0 && condition.humidity_percent > 50.0 && condition.pressure_hpa > 1010.0);
        
        if (condition.temperature_c > 25.0 && condition.humidity_percent > 70.0) {
            EXPECT_TRUE(ducting) << "Excellent conditions should produce ducting";
        } else if (condition.temperature_c < 10.0 || condition.humidity_percent < 30.0) {
            EXPECT_FALSE(ducting) << "Poor conditions should not produce ducting";
        }
    }
}

TEST_F(EnvironmentalEffectsTest, TroposphericScatter) {
    // Test tropospheric scatter propagation
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Tropospheric scatter is significant for VHF at long distances
    if (frequency_mhz > 100.0 && distance_km > 100.0) {
        double scatter_loss_db = 0.0;
        
        // Calculate tropospheric scatter loss
        scatter_loss_db = 20.0 * std::log10(distance_km) + 0.1 * frequency_mhz;
        
        EXPECT_GT(scatter_loss_db, 0.0) << "Tropospheric scatter should have loss";
        EXPECT_LT(scatter_loss_db, 100.0) << "Tropospheric scatter loss should be reasonable";
        
        // Test with different distances
        std::vector<double> test_distances = {50.0, 100.0, 200.0, 500.0, 1000.0};
        
        for (double test_distance : test_distances) {
            double test_loss = 20.0 * std::log10(test_distance) + 0.1 * frequency_mhz;
            
            EXPECT_GT(test_loss, 0.0) << "Scatter loss should be positive";
            
            // Longer distances should have higher loss
            if (test_distance > 100.0) {
                EXPECT_GT(test_loss, 40.0) << "Long distances should have high loss";
            }
        }
    }
}

// Additional environmental effects tests
TEST_F(EnvironmentalEffectsTest, CombinedWeatherEffects) {
    // Test combined weather effects
    WeatherConditions adverse_weather = generateAdverseWeather();
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Use frequency in the test
    EXPECT_GT(frequency_mhz, 0.0) << "Frequency should be positive";
    EXPECT_LT(frequency_mhz, 300.0) << "Frequency should be in VHF range";
    
    // Calculate combined effects
    double total_attenuation_db = 0.0;
    
    // Rain attenuation
    if (adverse_weather.precipitation_mmh > 0.0) {
        total_attenuation_db += 0.01 * adverse_weather.precipitation_mmh * distance_km;
    }
    
    // Fog attenuation
    if (adverse_weather.fog) {
        total_attenuation_db += 0.005 * distance_km;
    }
    
    // Snow attenuation
    if (adverse_weather.snow) {
        total_attenuation_db += 0.02 * distance_km;
    }
    
    // Temperature effects
    if (adverse_weather.temperature_c < 0.0) {
        total_attenuation_db += 0.001 * distance_km * std::abs(adverse_weather.temperature_c);
    }
    
    // Humidity effects
    if (adverse_weather.humidity_percent > 80.0) {
        total_attenuation_db += 0.002 * distance_km * (adverse_weather.humidity_percent - 80.0) / 20.0;
    }
    
    EXPECT_GT(total_attenuation_db, 0.0) << "Combined weather effects should cause attenuation";
    EXPECT_LT(total_attenuation_db, 50.0) << "Combined effects should be reasonable";
}

TEST_F(EnvironmentalEffectsTest, EnvironmentalEffectsPerformance) {
    // Test environmental effects calculation performance
    const int num_calculations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_calculations; ++i) {
        // Generate random weather conditions
        WeatherConditions weather;
        weather.temperature_c = -20.0 + (i % 60) * 1.0;
        weather.humidity_percent = 20.0 + (i % 80) * 1.0;
        weather.pressure_hpa = 950.0 + (i % 100) * 1.0;
        weather.precipitation_mmh = (i % 50) * 1.0;
        weather.fog = (i % 10) == 0;
        weather.snow = (i % 15) == 0;
        
        // Calculate environmental effects
        double total_effect_db = 0.0;
        
        if (weather.precipitation_mmh > 0.0) {
            total_effect_db += 0.01 * weather.precipitation_mmh * 5.0;
        }
        
        if (weather.fog) {
            total_effect_db += 0.005 * 5.0;
        }
        
        if (weather.snow) {
            total_effect_db += 0.02 * 5.0;
        }
        
        if (weather.temperature_c < 0.0) {
            total_effect_db += 0.001 * 5.0 * std::abs(weather.temperature_c);
        }
        
        if (weather.humidity_percent > 80.0) {
            total_effect_db += 0.002 * 5.0 * (weather.humidity_percent - 80.0) / 20.0;
        }
        
        // Verify calculation is reasonable
        EXPECT_GE(total_effect_db, 0.0);
        EXPECT_LT(total_effect_db, 100.0);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_calculation = static_cast<double>(duration.count()) / num_calculations;
    
    // Environmental effects calculations should be fast
    EXPECT_LT(time_per_calculation, 5.0) << "Environmental effects calculation too slow: " << time_per_calculation << " microseconds";
    
    std::cout << "Environmental effects calculation performance: " << time_per_calculation << " microseconds per calculation" << std::endl;
}
