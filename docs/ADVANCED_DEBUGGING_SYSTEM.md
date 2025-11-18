# Advanced Debugging System Documentation

## Overview

The FGCom-mumble Advanced Debugging System provides comprehensive logging, profiling, and memory tracking capabilities for monitoring system performance, diagnosing issues, and optimizing resource usage.

## System Architecture

### Core Components

- **DebuggingSystem**: Central debugging and monitoring system
- **PerformanceProfiler**: CPU and operation timing analysis
- **MemoryUsageTracker**: Memory allocation and leak detection
- **DebugOutputHandler**: Configurable output destinations
- **ThreadMonitor**: Thread operation monitoring
- **NetworkMonitor**: Network traffic analysis

## Debugging Categories

### 1. Radio Communication
- **Frequency Changes**: Monitor frequency tuning operations
- **Signal Strength**: Track signal strength variations
- **Propagation Calculations**: Debug propagation modeling
- **Channel Operations**: Monitor channel switching and management

### 2. Audio Processing
- **Audio Pipeline**: Monitor audio processing pipeline
- **Filter Operations**: Debug filter application and performance
- **Compression/Decompression**: Track audio compression operations
- **Latency Monitoring**: Measure audio processing latency

### 3. Network Operations
- **UDP Traffic**: Monitor UDP communication
- **TCP Connections**: Track TCP connection management
- **WebSocket Events**: Monitor WebSocket real-time communication
- **API Requests**: Log API request/response cycles

### 4. Threading Operations
- **Thread Creation/Destruction**: Monitor thread lifecycle
- **Thread Synchronization**: Debug mutex and lock operations
- **Thread Performance**: Track thread CPU usage and efficiency
- **Thread Communication**: Monitor inter-thread communication

### 5. Memory Management
- **Allocation Tracking**: Monitor memory allocations
- **Deallocation Tracking**: Track memory deallocations
- **Leak Detection**: Identify memory leaks
- **Peak Usage**: Monitor peak memory consumption

### 6. GPU Operations
- **GPU Utilization**: Monitor GPU usage
- **GPU Memory**: Track GPU memory allocation
- **GPU Performance**: Measure GPU operation performance
- **GPU Temperature**: Monitor GPU thermal conditions

### 7. Performance Monitoring
- **CPU Usage**: Track CPU utilization
- **Memory Usage**: Monitor system memory usage
- **Network Performance**: Measure network throughput
- **Disk I/O**: Monitor file system operations

## Debug Levels

### 1. TRACE
- **Purpose**: Detailed execution flow
- **Usage**: Function entry/exit, variable values
- **Performance Impact**: High
- **Example**: Function call tracing, variable state changes

### 2. DEBUG
- **Purpose**: Development debugging
- **Usage**: Algorithm steps, intermediate results
- **Performance Impact**: Medium
- **Example**: Calculation steps, decision points

### 3. INFO
- **Purpose**: General information
- **Usage**: System status, user actions
- **Performance Impact**: Low
- **Example**: System startup, configuration changes

### 4. WARNING
- **Purpose**: Potential issues
- **Usage**: Non-critical errors, performance issues
- **Performance Impact**: Low
- **Example**: Resource usage warnings, deprecated features

### 5. ERROR
- **Purpose**: Error conditions
- **Usage**: Failed operations, invalid states
- **Performance Impact**: Low
- **Example**: Network failures, calculation errors

### 6. CRITICAL
- **Purpose**: Critical failures
- **Usage**: System failures, data corruption
- **Performance Impact**: Low
- **Example**: Memory corruption, system crashes

## Configuration

### Debug Configuration File

```ini
# configs/debugging.conf
[debugging]
# Main debugging settings
enable_debug_mode = false
debug_level = info
log_to_file = true
log_to_console = true
log_file_path = /tmp/fgcom-debug.log
max_log_file_size = 10485760  # 10MB
log_rotation_count = 5

# Performance monitoring
enable_performance_monitoring = false
performance_sampling_interval = 1000  # milliseconds
enable_cpu_monitoring = false
enable_memory_monitoring = false
enable_thread_monitoring = false

# Memory tracking
enable_memory_tracking = false
track_allocations = false
track_deallocations = false
track_memory_leaks = false
memory_check_interval = 5000  # milliseconds

# Thread monitoring
enable_thread_monitoring = false
monitor_thread_creation = false
monitor_thread_destruction = false
monitor_thread_switches = false
thread_check_interval = 1000  # milliseconds

# Network monitoring
enable_network_monitoring = false
monitor_udp_traffic = false
monitor_tcp_traffic = false
monitor_websocket_traffic = false
network_check_interval = 2000  # milliseconds

# Audio monitoring
enable_audio_monitoring = false
monitor_audio_processing = false
monitor_audio_quality = false
monitor_audio_latency = false
audio_check_interval = 500  # milliseconds

# Radio monitoring
enable_radio_monitoring = false
monitor_frequency_changes = false
monitor_signal_strength = false
monitor_propagation_calculations = false
radio_check_interval = 1000  # milliseconds

# Error tracking
enable_error_tracking = true
track_critical_errors = true
track_warnings = true
track_info_messages = false
error_reporting_threshold = 10
```

### Logging Categories

```ini
[logging_categories]
enable_radio_logging = false
enable_audio_logging = false
enable_network_logging = false
enable_thread_logging = false
enable_memory_logging = false
enable_performance_logging = false
enable_security_logging = false
enable_api_logging = false
```

### Debug Output Settings

```ini
[debug_output]
enable_timestamp = true
enable_thread_id = false
enable_function_name = false
enable_file_location = false
enable_line_number = false
enable_color_output = true
```

## Usage Examples

### Basic Logging

#### C++ API Usage
```cpp
#include "debugging_system.h"

// Get debugging system instance
auto& debug_system = FGCom_DebuggingSystem::getInstance();

// Basic logging
debug_system.info(DebugCategory::RADIO, "Radio system initialized");
debug_system.warning(DebugCategory::AUDIO, "Audio buffer underrun detected");
debug_system.error(DebugCategory::NETWORK, "Network connection failed");

// Detailed logging with context
debug_system.debug(DebugCategory::PROPAGATION, 
    "Propagation calculation completed", 
    __FILE__, __LINE__, __FUNCTION__);
```

#### Macro Usage
```cpp
// Use convenience macros
FGCOM_LOG_INFO(DebugCategory::RADIO, "Radio frequency changed to 121.5 MHz");
FGCOM_LOG_DEBUG(DebugCategory::AUDIO, "Audio processing started");
FGCOM_LOG_ERROR(DebugCategory::NETWORK, "Connection timeout");
FGCOM_LOG_CRITICAL(DebugCategory::MEMORY, "Memory allocation failed");
```

### Performance Profiling

#### Operation Profiling
```cpp
// Start profiling an operation
debug_system.startProfile("antenna_calculation");

// ... perform antenna calculation ...

// End profiling
debug_system.endProfile("antenna_calculation");

// Get profiling results
auto profile_data = debug_system.getProfileData("antenna_calculation");
std::cout << "Operation took: " << profile_data.duration_ms << "ms" << std::endl;
std::cout << "Peak memory: " << profile_data.peak_memory << " bytes" << std::endl;
```

#### Scope-based Profiling
```cpp
// Use scope-based profiling for automatic cleanup
{
    FGCOM_PROFILE_SCOPE("propagation_modeling");
    
    // ... perform propagation modeling ...
    
    // Profile automatically ends when scope exits
}
```

#### Performance Monitoring
```cpp
// Enable performance monitoring
debug_system.enablePerformanceMonitoring(true);

// Monitor specific operations
debug_system.monitorOperation("audio_processing", [&]() {
    // ... audio processing code ...
});

// Get performance statistics
auto stats = debug_system.getPerformanceStatistics();
std::cout << "Average CPU usage: " << stats.cpu_usage_percent << "%" << std::endl;
std::cout << "Memory usage: " << stats.memory_usage_mb << " MB" << std::endl;
```

### Memory Tracking

#### Allocation Tracking
```cpp
// Track memory allocations
debug_system.recordAllocation("pattern_cache", 1024 * 1024);  // 1MB
debug_system.recordAllocation("audio_buffer", 512 * 1024);    // 512KB

// Track deallocations
debug_system.recordDeallocation("pattern_cache", 1024 * 1024);

// Record peak usage
debug_system.recordPeakUsage("total_memory", 2048 * 1024);  // 2MB peak
```

#### Memory Leak Detection
```cpp
// Enable memory leak detection
debug_system.enableMemoryLeakDetection(true);

// Track allocations with metadata
std::map<std::string, std::string> metadata;
metadata["function"] = "loadAntennaPattern";
metadata["file"] = "antenna_patterns.cpp";
metadata["line"] = "42";

debug_system.recordAllocation("antenna_data", 2048, metadata);

// Check for leaks
auto leaks = debug_system.detectMemoryLeaks();
if (!leaks.empty()) {
    std::cout << "Memory leaks detected:" << std::endl;
    for (const auto& leak : leaks) {
        std::cout << "  - " << leak.name << ": " << leak.size << " bytes" << std::endl;
    }
}
```

#### Memory Usage Reports
```cpp
// Generate memory usage report
auto memory_report = debug_system.generateMemoryReport();
std::cout << "Memory Usage Report:" << std::endl;
std::cout << "Total Allocated: " << memory_report.total_allocated << " bytes" << std::endl;
std::cout << "Peak Usage: " << memory_report.peak_usage << " bytes" << std::endl;
std::cout << "Current Usage: " << memory_report.current_usage << " bytes" << std::endl;
std::cout << "Leaks Detected: " << memory_report.leak_count << std::endl;
```

### Thread Monitoring

#### Thread Lifecycle Tracking
```cpp
// Monitor thread creation
debug_system.monitorThreadCreation("solar_data_thread", [&]() {
    // ... thread creation code ...
});

// Monitor thread destruction
debug_system.monitorThreadDestruction("solar_data_thread", [&]() {
    // ... thread cleanup code ...
});

// Track thread performance
debug_system.trackThreadPerformance("solar_data_thread", [&]() {
    // ... thread work ...
});
```

#### Thread Synchronization Debugging
```cpp
// Debug mutex operations
debug_system.debugMutexOperation("pattern_cache_mutex", "lock", [&]() {
    std::lock_guard<std::mutex> lock(pattern_cache_mutex);
    // ... critical section ...
});

// Debug condition variable operations
debug_system.debugConditionVariable("data_ready_cv", "wait", [&]() {
    std::unique_lock<std::mutex> lock(data_mutex);
    data_ready_cv.wait(lock, [&]() { return data_ready; });
});
```

### Network Monitoring

#### Traffic Analysis
```cpp
// Monitor UDP traffic
debug_system.monitorUDPTraffic("radio_communication", [&]() {
    // ... UDP operations ...
});

// Monitor TCP connections
debug_system.monitorTCPConnection("api_server", [&]() {
    // ... TCP operations ...
});

// Monitor WebSocket events
debug_system.monitorWebSocketEvent("real_time_updates", [&]() {
    // ... WebSocket operations ...
});
```

#### Network Performance
```cpp
// Track network performance
auto network_stats = debug_system.getNetworkStatistics();
std::cout << "UDP Packets Sent: " << network_stats.udp_packets_sent << std::endl;
std::cout << "TCP Connections: " << network_stats.tcp_connections << std::endl;
std::cout << "WebSocket Events: " << network_stats.websocket_events << std::endl;
std::cout << "Network Latency: " << network_stats.average_latency_ms << "ms" << std::endl;
```

## Advanced Features

### Remote Debugging

#### Remote Debug Configuration
```ini
[remote_debugging]
enable_remote_debugging = false
remote_debug_port = 9999
remote_debug_host = localhost
enable_remote_logging = false
remote_log_port = 9998
remote_log_host = localhost
```

#### Remote Debug Usage
```cpp
// Enable remote debugging
debug_system.enableRemoteDebugging("localhost", 9999);

// Send debug data to remote host
debug_system.sendToRemote("debug_data", debug_information);

// Receive remote debug commands
debug_system.setRemoteCommandHandler([](const std::string& command) {
    if (command == "dump_memory") {
        auto memory_dump = debug_system.generateMemoryDump();
        debug_system.sendToRemote("memory_dump", memory_dump);
    }
});
```

### Profiling and Analysis

#### Call Graph Generation
```cpp
// Enable call graph profiling
debug_system.enableCallGraph(true);

// Profile function calls
debug_system.profileFunctionCall("calculatePropagation", [&]() {
    // ... propagation calculation ...
});

// Generate call graph
auto call_graph = debug_system.generateCallGraph();
std::cout << "Call Graph:" << std::endl;
for (const auto& node : call_graph.nodes) {
    std::cout << "  " << node.function_name << " -> " << node.called_functions.size() << " functions" << std::endl;
}
```

#### Performance Analysis
```cpp
// Enable performance analysis
debug_system.enablePerformanceAnalysis(true);

// Analyze performance bottlenecks
auto bottlenecks = debug_system.identifyBottlenecks();
std::cout << "Performance Bottlenecks:" << std::endl;
for (const auto& bottleneck : bottlenecks) {
    std::cout << "  - " << bottleneck.operation_name << ": " << bottleneck.impact_percent << "% impact" << std::endl;
}

// Generate performance report
auto perf_report = debug_system.generatePerformanceReport();
std::cout << "Performance Report:" << std::endl;
std::cout << "Total Operations: " << perf_report.total_operations << std::endl;
std::cout << "Average Duration: " << perf_report.average_duration_ms << "ms" << std::endl;
std::cout << "Peak Duration: " << perf_report.peak_duration_ms << "ms" << std::endl;
```

### Crash Reporting

#### Crash Detection
```cpp
// Enable crash reporting
debug_system.enableCrashReporting(true);

// Set crash handler
debug_system.setCrashHandler([](const CrashInfo& crash_info) {
    std::cout << "Crash detected:" << std::endl;
    std::cout << "  Signal: " << crash_info.signal << std::endl;
    std::cout << "  Address: " << crash_info.address << std::endl;
    std::cout << "  Thread: " << crash_info.thread_id << std::endl;
    
    // Generate crash report
    auto crash_report = debug_system.generateCrashReport(crash_info);
    debug_system.saveCrashReport(crash_report, "/tmp/fgcom-crash.json");
});
```

#### Stack Trace Generation
```cpp
// Generate stack trace
auto stack_trace = debug_system.generateStackTrace();
std::cout << "Stack Trace:" << std::endl;
for (const auto& frame : stack_trace.frames) {
    std::cout << "  " << frame.function_name << " (" << frame.file_name << ":" << frame.line_number << ")" << std::endl;
}
```

## Output Handlers

### File Output Handler
```cpp
// Configure file output
debug_system.addOutputHandler(std::make_unique<FileOutputHandler>(
    "/tmp/fgcom-debug.log",
    10 * 1024 * 1024,  // 10MB max size
    5                  // 5 rotation files
));
```

### Console Output Handler
```cpp
// Configure console output with colors
debug_system.addOutputHandler(std::make_unique<ConsoleOutputHandler>(
    true,  // enable colors
    true   // enable timestamps
));
```

### Network Output Handler
```cpp
// Configure network output
debug_system.addOutputHandler(std::make_unique<NetworkOutputHandler>(
    "localhost",
    9999,
    true  // enable compression
));
```

### Database Output Handler
```cpp
// Configure database output
debug_system.addOutputHandler(std::make_unique<DatabaseOutputHandler>(
    "debug_logs",
    "localhost",
    5432,
    "fgcom_debug"
));
```

## Best Practices

### Development Environment
```ini
# Enable comprehensive debugging
enable_debug_mode = true
debug_level = debug
enable_performance_monitoring = true
enable_memory_tracking = true
enable_thread_monitoring = true
enable_network_monitoring = true
```

### Production Environment
```ini
# Enable only essential debugging
enable_debug_mode = false
debug_level = warning
enable_performance_monitoring = false
enable_memory_tracking = false
enable_thread_monitoring = false
enable_network_monitoring = false
```

### Performance Testing
```ini
# Enable performance monitoring only
enable_debug_mode = false
debug_level = info
enable_performance_monitoring = true
enable_memory_tracking = true
enable_thread_monitoring = false
enable_network_monitoring = false
```

## Troubleshooting

### Common Issues

#### High Memory Usage
1. **Check memory tracking**: Ensure memory tracking is properly configured
2. **Review allocations**: Use memory reports to identify large allocations
3. **Check for leaks**: Run memory leak detection
4. **Optimize caching**: Review cache sizes and cleanup policies

#### Performance Degradation
1. **Disable debugging**: Turn off debug mode in production
2. **Reduce log level**: Use higher log levels (WARNING, ERROR)
3. **Limit output**: Configure output handlers appropriately
4. **Monitor impact**: Use performance profiling to measure impact

#### Log File Issues
1. **Check permissions**: Ensure write permissions for log files
2. **Monitor disk space**: Check available disk space
3. **Configure rotation**: Set appropriate log rotation settings
4. **Review filters**: Use debug filters to reduce log volume

### Diagnostic Tools

#### System Health Check
```cpp
// Perform system health check
auto health_check = debug_system.performHealthCheck();
std::cout << "System Health Check:" << std::endl;
std::cout << "  Status: " << (health_check.healthy ? "HEALTHY" : "UNHEALTHY") << std::endl;
std::cout << "  Issues: " << health_check.issue_count << std::endl;
std::cout << "  Warnings: " << health_check.warning_count << std::endl;
```

#### Configuration Validation
```cpp
// Validate debugging configuration
auto validation = debug_system.validateConfiguration();
if (validation.is_valid) {
    std::cout << "Configuration is valid" << std::endl;
} else {
    std::cout << "Configuration errors:" << std::endl;
    for (const auto& error : validation.errors) {
        std::cout << "  - " << error << std::endl;
    }
}
```

This comprehensive debugging system provides powerful tools for monitoring, profiling, and diagnosing FGCom-mumble's operation across all system components.
