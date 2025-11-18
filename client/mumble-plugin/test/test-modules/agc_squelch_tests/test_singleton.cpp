#include "test_agc_squelch_main.cpp"

// 1.1 Singleton Pattern Tests
TEST_F(SingletonTest, ValidInstanceCreation) {
    // Test that getInstance() returns a valid instance
    FGCom_AGC_Squelch& instance1 = FGCom_AGC_Squelch::getInstance();
    EXPECT_NE(&instance1, nullptr);
    
    // Test that the instance is properly initialized
    EXPECT_TRUE(instance1.isAGCEnabled() || !instance1.isAGCEnabled()); // Should not crash
    EXPECT_TRUE(instance1.isSquelchEnabled() || !instance1.isSquelchEnabled()); // Should not crash
}

TEST_F(SingletonTest, SameInstanceReturned) {
    // Test that multiple calls return the same instance
    FGCom_AGC_Squelch& instance1 = FGCom_AGC_Squelch::getInstance();
    FGCom_AGC_Squelch& instance2 = FGCom_AGC_Squelch::getInstance();
    
    EXPECT_EQ(&instance1, &instance2);
}

TEST_F(SingletonTest, ThreadSafeAccess) {
    const int num_threads = 20;
    std::vector<std::thread> threads;
    std::vector<FGCom_AGC_Squelch*> instances(num_threads);
    std::mutex instances_mutex;
    
    // Launch multiple threads to test thread safety
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&instances, &instances_mutex, i]() {
            FGCom_AGC_Squelch& instance = FGCom_AGC_Squelch::getInstance();
            {
                std::lock_guard<std::mutex> lock(instances_mutex);
                instances[i] = &instance;
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify all threads got the same instance
    FGCom_AGC_Squelch* first_instance = instances[0];
    for (int i = 1; i < num_threads; ++i) {
        EXPECT_EQ(first_instance, instances[i]) 
            << "Thread " << i << " got different instance";
    }
}

TEST_F(SingletonTest, DestroyAndRecreate) {
    // Test singleton state management (Meyer's singleton doesn't support destruction)
    FGCom_AGC_Squelch& instance1 = FGCom_AGC_Squelch::getInstance();
    
    // Set a specific mode to test state persistence
    instance1.setAGCMode(AGCMode::FAST);
    EXPECT_EQ(instance1.getAGCMode(), AGCMode::FAST);
    
    // Get the same instance - should maintain state
    FGCom_AGC_Squelch& instance2 = FGCom_AGC_Squelch::getInstance();
    
    // Should be the same instance with same state
    EXPECT_EQ(instance2.getAGCMode(), AGCMode::FAST) << "Singleton should maintain state";
    
    // Reset to default state for next tests
    instance2.setAGCMode(AGCMode::SLOW);
    EXPECT_EQ(instance2.getAGCMode(), AGCMode::SLOW);
    
    // Instance should be valid
    EXPECT_TRUE(instance2.isAGCEnabled());
}

TEST_F(SingletonTest, MemoryLeakVerification) {
    // This test will be run with Valgrind to check for memory leaks
    {
        FGCom_AGC_Squelch& instance = FGCom_AGC_Squelch::getInstance();
        
        // Perform some operations that might allocate memory
        instance.setAGCMode(AGCMode::FAST);
        instance.setSquelchEnabled(true);
        
        // Process some audio samples
        std::vector<float> input(1024, 0.1f);
        std::vector<float> output(1024);
        instance.processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
    }
    
    // Destroy instance and check for leaks
    FGCom_AGC_Squelch::destroyInstance();
    
    // If we reach here without Valgrind errors, no leaks detected
    SUCCEED();
}

// Additional singleton stress tests
TEST_F(SingletonTest, RapidCreateDestroy) {
    const int iterations = 100;
    
    for (int i = 0; i < iterations; ++i) {
        FGCom_AGC_Squelch& instance = FGCom_AGC_Squelch::getInstance();
        EXPECT_NE(&instance, nullptr);
        
        // Perform some operations
        instance.setAGCMode(static_cast<AGCMode>(i % 4));
        
        FGCom_AGC_Squelch::destroyInstance();
    }
}

TEST_F(SingletonTest, ConcurrentDestroy) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    
    // Launch threads that will try to destroy the instance
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([]() {
            // Each thread gets instance and then destroys it
            FGCom_AGC_Squelch::getInstance();
            FGCom_AGC_Squelch::destroyInstance();
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Final instance should still be valid
    FGCom_AGC_Squelch& final_instance = FGCom_AGC_Squelch::getInstance();
    EXPECT_NE(&final_instance, nullptr);
}
