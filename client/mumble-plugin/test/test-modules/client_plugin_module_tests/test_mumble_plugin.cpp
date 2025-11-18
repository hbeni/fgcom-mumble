#include "test_client_plugin_module_main.cpp"

// 8.1 Mumble Plugin Tests
TEST_F(MumblePluginTest, PluginInitialization) {
    // Test plugin initialization
    EXPECT_FALSE(mock_mumble_plugin->isInitialized()) << "Plugin should not be initialized initially";
    
    bool init_result = mock_mumble_plugin->initialize();
    EXPECT_TRUE(init_result) << "Plugin initialization should succeed";
    EXPECT_TRUE(mock_mumble_plugin->isInitialized()) << "Plugin should be initialized after init";
    
    // Test plugin shutdown
    mock_mumble_plugin->shutdown();
    EXPECT_FALSE(mock_mumble_plugin->isInitialized()) << "Plugin should not be initialized after shutdown";
}

TEST_F(MumblePluginTest, AudioCallbackRegistration) {
    // Test audio callback registration
    std::atomic<bool> callback_called{false};
    std::vector<float> received_samples;
    
    auto audio_callback = [&](const float* samples, size_t sample_count) {
        callback_called = true;
        received_samples.assign(samples, samples + sample_count);
    };
    
    // Test callback registration
    bool reg_result = mock_mumble_plugin->registerAudioCallback(audio_callback);
    EXPECT_TRUE(reg_result) << "Audio callback registration should succeed";
    
    // Test audio processing
    std::vector<float> test_samples = generateAudioSamples(test_audio_samples);
    mock_mumble_plugin->processAudio(test_samples.data(), test_samples.size());
    
    // Wait for callback to be called
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    EXPECT_TRUE(callback_called.load()) << "Audio callback should be called";
    EXPECT_EQ(received_samples.size(), test_samples.size()) << "Received samples should match input";
    
    // Test callback unregistration
    mock_mumble_plugin->unregisterAudioCallback();
    
    // Test that callback is no longer called
    callback_called = false;
    received_samples.clear();
    
    mock_mumble_plugin->processAudio(test_samples.data(), test_samples.size());
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    EXPECT_FALSE(callback_called.load()) << "Audio callback should not be called after unregistration";
}

TEST_F(MumblePluginTest, PositionDataExtraction) {
    // Test position data extraction
    mock_mumble_plugin->enablePositionalData();
    EXPECT_TRUE(mock_mumble_plugin->isPositionalDataEnabled()) << "Positional data should be enabled";
    
    // Set test position data
    float test_x = 1000.0f, test_y = 2000.0f, test_z = 3000.0f;
    mock_mumble_plugin->setPosition(test_x, test_y, test_z);
    
    float test_dir_x = 1.0f, test_dir_y = 0.0f, test_dir_z = 0.0f;
    mock_mumble_plugin->setDirection(test_dir_x, test_dir_y, test_dir_z);
    
    float test_axis_x = 0.0f, test_axis_y = 0.0f, test_axis_z = 1.0f;
    mock_mumble_plugin->setAxis(test_axis_x, test_axis_y, test_axis_z);
    
    float test_cam_x = 1000.0f, test_cam_y = 2000.0f, test_cam_z = 3000.0f;
    mock_mumble_plugin->setCameraPosition(test_cam_x, test_cam_y, test_cam_z);
    
    float test_cam_dir_x = 1.0f, test_cam_dir_y = 0.0f, test_cam_dir_z = 0.0f;
    mock_mumble_plugin->setCameraDirection(test_cam_dir_x, test_cam_dir_y, test_cam_dir_z);
    
    float test_cam_axis_x = 0.0f, test_cam_axis_y = 0.0f, test_cam_axis_z = 1.0f;
    mock_mumble_plugin->setCameraAxis(test_cam_axis_x, test_cam_axis_y, test_cam_axis_z);
    
    // Test position data extraction
    float avatarPos[3], avatarDir[3], avatarAxis[3];
    float cameraPos[3], cameraDir[3], cameraAxis[3];
    const char* context, *identity;
    
    bool fetch_result = mock_mumble_plugin->fetchPositionalData(
        avatarPos, avatarDir, avatarAxis,
        cameraPos, cameraDir, cameraAxis,
        &context, &identity
    );
    
    EXPECT_TRUE(fetch_result) << "Position data extraction should succeed";
    
    // Validate avatar position
    EXPECT_FLOAT_EQ(avatarPos[0], test_x) << "Avatar X position should match";
    EXPECT_FLOAT_EQ(avatarPos[1], test_y) << "Avatar Y position should match";
    EXPECT_FLOAT_EQ(avatarPos[2], test_z) << "Avatar Z position should match";
    
    // Validate avatar direction
    EXPECT_FLOAT_EQ(avatarDir[0], test_dir_x) << "Avatar direction X should match";
    EXPECT_FLOAT_EQ(avatarDir[1], test_dir_y) << "Avatar direction Y should match";
    EXPECT_FLOAT_EQ(avatarDir[2], test_dir_z) << "Avatar direction Z should match";
    
    // Validate avatar axis
    EXPECT_FLOAT_EQ(avatarAxis[0], test_axis_x) << "Avatar axis X should match";
    EXPECT_FLOAT_EQ(avatarAxis[1], test_axis_y) << "Avatar axis Y should match";
    EXPECT_FLOAT_EQ(avatarAxis[2], test_axis_z) << "Avatar axis Z should match";
    
    // Validate camera position
    EXPECT_FLOAT_EQ(cameraPos[0], test_cam_x) << "Camera X position should match";
    EXPECT_FLOAT_EQ(cameraPos[1], test_cam_y) << "Camera Y position should match";
    EXPECT_FLOAT_EQ(cameraPos[2], test_cam_z) << "Camera Z position should match";
    
    // Validate camera direction
    EXPECT_FLOAT_EQ(cameraDir[0], test_cam_dir_x) << "Camera direction X should match";
    EXPECT_FLOAT_EQ(cameraDir[1], test_cam_dir_y) << "Camera direction Y should match";
    EXPECT_FLOAT_EQ(cameraDir[2], test_cam_dir_z) << "Camera direction Z should match";
    
    // Validate camera axis
    EXPECT_FLOAT_EQ(cameraAxis[0], test_cam_axis_x) << "Camera axis X should match";
    EXPECT_FLOAT_EQ(cameraAxis[1], test_cam_axis_y) << "Camera axis Y should match";
    EXPECT_FLOAT_EQ(cameraAxis[2], test_cam_axis_z) << "Camera axis Z should match";
    
    // Validate context and identity
    EXPECT_NE(context, nullptr) << "Context should not be null";
    EXPECT_NE(identity, nullptr) << "Identity should not be null";
    EXPECT_GT(strlen(context), 0) << "Context should not be empty";
    EXPECT_GT(strlen(identity), 0) << "Identity should not be empty";
}

TEST_F(MumblePluginTest, ContextDetection) {
    // Test context detection
    bool context_result = mock_mumble_plugin->detectContext();
    EXPECT_TRUE(context_result) << "Context detection should succeed";
    
    // Test position data extraction with context
    mock_mumble_plugin->enablePositionalData();
    
    float avatarPos[3], avatarDir[3], avatarAxis[3];
    float cameraPos[3], cameraDir[3], cameraAxis[3];
    const char* context, *identity;
    
    bool fetch_result = mock_mumble_plugin->fetchPositionalData(
        avatarPos, avatarDir, avatarAxis,
        cameraPos, cameraDir, cameraAxis,
        &context, &identity
    );
    
    EXPECT_TRUE(fetch_result) << "Position data extraction with context should succeed";
    
    // Validate context format
    std::string context_str(context);
    EXPECT_TRUE(context_str.find("flightgear") != std::string::npos) << "Context should contain flightgear";
    EXPECT_TRUE(context_str.find("server") != std::string::npos) << "Context should contain server";
    EXPECT_TRUE(context_str.find("team") != std::string::npos) << "Context should contain team";
    
    // Validate identity format
    std::string identity_str(identity);
    EXPECT_TRUE(identity_str.find("pilot_") != std::string::npos) << "Identity should contain pilot_";
}

TEST_F(MumblePluginTest, PluginShutdownCleanup) {
    // Test plugin shutdown cleanup
    EXPECT_FALSE(mock_mumble_plugin->isInitialized()) << "Plugin should not be initialized initially";
    
    // Initialize plugin
    bool init_result = mock_mumble_plugin->initialize();
    EXPECT_TRUE(init_result) << "Plugin initialization should succeed";
    EXPECT_TRUE(mock_mumble_plugin->isInitialized()) << "Plugin should be initialized";
    
    // Register audio callback
    std::atomic<bool> callback_called{false};
    auto audio_callback = [&](const float* samples, size_t sample_count) {
        // Use parameters to avoid unused parameter warnings
        callback_called = (samples != nullptr && sample_count > 0);
    };
    
    bool reg_result = mock_mumble_plugin->registerAudioCallback(audio_callback);
    EXPECT_TRUE(reg_result) << "Audio callback registration should succeed";
    
    // Enable positional data
    mock_mumble_plugin->enablePositionalData();
    EXPECT_TRUE(mock_mumble_plugin->isPositionalDataEnabled()) << "Positional data should be enabled";
    
    // Test shutdown cleanup
    mock_mumble_plugin->shutdown();
    
    EXPECT_FALSE(mock_mumble_plugin->isInitialized()) << "Plugin should not be initialized after shutdown";
    EXPECT_FALSE(mock_mumble_plugin->isPositionalDataEnabled()) << "Positional data should be disabled after shutdown";
    
    // Test that audio callback is no longer called
    callback_called = false;
    std::vector<float> test_samples = generateAudioSamples(test_audio_samples);
    mock_mumble_plugin->processAudio(test_samples.data(), test_samples.size());
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    EXPECT_FALSE(callback_called.load()) << "Audio callback should not be called after shutdown";
}

// Additional Mumble plugin tests
TEST_F(MumblePluginTest, PluginPerformance) {
    // Test plugin performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test initialization performance
    for (int i = 0; i < num_operations; ++i) {
        mock_mumble_plugin->initialize();
        mock_mumble_plugin->shutdown();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Plugin operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "Plugin operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Plugin performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(MumblePluginTest, PluginAccuracy) {
    // Test plugin accuracy
    mock_mumble_plugin->initialize();
    mock_mumble_plugin->enablePositionalData();
    
    // Set precise test data
    float test_x = 1234.567f, test_y = 2345.678f, test_z = 3456.789f;
    mock_mumble_plugin->setPosition(test_x, test_y, test_z);
    
    // Test position data accuracy
    float avatarPos[3], avatarDir[3], avatarAxis[3];
    float cameraPos[3], cameraDir[3], cameraAxis[3];
    const char* context, *identity;
    
    bool fetch_result = mock_mumble_plugin->fetchPositionalData(
        avatarPos, avatarDir, avatarAxis,
        cameraPos, cameraDir, cameraAxis,
        &context, &identity
    );
    
    EXPECT_TRUE(fetch_result) << "Position data extraction should succeed";
    
    // Test position accuracy
    EXPECT_FLOAT_EQ(avatarPos[0], test_x) << "Avatar X position should be accurate";
    EXPECT_FLOAT_EQ(avatarPos[1], test_y) << "Avatar Y position should be accurate";
    EXPECT_FLOAT_EQ(avatarPos[2], test_z) << "Avatar Z position should be accurate";
    
    // Test audio callback accuracy
    std::atomic<int> callback_count{0};
    std::vector<float> received_samples;
    
    auto audio_callback = [&](const float* samples, size_t sample_count) {
        callback_count++;
        received_samples.assign(samples, samples + sample_count);
    };
    
    bool reg_result = mock_mumble_plugin->registerAudioCallback(audio_callback);
    EXPECT_TRUE(reg_result) << "Audio callback registration should succeed";
    
    // Test audio processing accuracy
    std::vector<float> test_samples = generateAudioSamples(test_audio_samples);
    mock_mumble_plugin->processAudio(test_samples.data(), test_samples.size());
    
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    EXPECT_EQ(callback_count.load(), 1) << "Audio callback should be called once";
    EXPECT_EQ(received_samples.size(), test_samples.size()) << "Received samples should match input";
    
    // Test sample accuracy
    for (size_t i = 0; i < test_samples.size(); ++i) {
        EXPECT_FLOAT_EQ(received_samples[i], test_samples[i]) << "Sample " << i << " should be accurate";
    }
}

