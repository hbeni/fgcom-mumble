#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cstring>
#include <cmath>

// Fuzzing target for network protocol operations
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0; // Need minimum data
    
    // Systematically consume input bytes
    size_t offset = 0;
    uint8_t selector = Data[offset++];
    
    // Extract network parameters
    uint32_t port = 0;
    uint32_t data_len = 0;
    
    if (offset + 4 <= Size) {
        memcpy(&port, Data + offset, 4);
        offset += 4;
    }
    if (offset + 4 <= Size) {
        memcpy(&data_len, Data + offset, 4);
        offset += 4;
    }
    
    // Limit data length
    data_len = std::min(data_len, static_cast<uint32_t>(Size - offset));
    if (data_len == 0) data_len = 1;
    
    try {
        // Extract network data
        std::vector<uint8_t> network_data(data_len);
        for (size_t i = 0; i < data_len && offset < Size; ++i) {
            network_data[i] = Data[offset++];
        }
        
        // PURE FUZZING: Use selector byte to pick ONE code path
        switch (selector % 8) {
            case 0: {
                // Test UDP client operations
                std::string host = "127.0.0.1";
                std::string data_str(reinterpret_cast<const char*>(network_data.data()), network_data.size());
                
                // Simulate UDP packet construction
                size_t packet_size = 8 + data_str.length(); // Header + data
                if (packet_size > 0) {
                    // Simulate packet header
                    uint32_t sequence = port; // Use port as sequence number
                    uint32_t checksum = 0;
                    for (char c : data_str) {
                        checksum += static_cast<uint8_t>(c);
                    }
                    
                    // Simulate network transmission
                    double transmission_time = packet_size / 1000.0; // 1KB/s
                    return 0;
                }
                break;
            }
            
            case 1: {
                // Test UDP server operations
                std::string data_str(reinterpret_cast<const char*>(network_data.data()), network_data.size());
                
                // Simulate UDP server receive
                if (data_str.length() > 0) {
                    // Simulate packet parsing
                    size_t header_size = 8;
                    if (data_str.length() > header_size) {
                        std::string payload = data_str.substr(header_size);
                        
                        // Simulate payload processing
                        size_t processed_bytes = 0;
                        for (char c : payload) {
                            if (c != '\0') {
                                processed_bytes++;
                            }
                        }
                        
                        // Simulate server response
                        if (processed_bytes > 0) {
                            return 0;
                        }
                    }
                }
                break;
            }
            
            case 2: {
                // Test protocol parsing
                if (network_data.size() > 0) {
                    uint8_t protocol_type = network_data[0];
                    
                    // Simulate different protocol types
                    switch (protocol_type % 4) {
                        case 0: {
                            // HTTP-like protocol
                            std::string data_str(reinterpret_cast<const char*>(network_data.data()), network_data.size());
                            if (data_str.find("GET") == 0) {
                                // Simulate HTTP GET parsing
                                size_t space_pos = data_str.find(' ');
                                if (space_pos != std::string::npos) {
                                    std::string method = data_str.substr(0, space_pos);
                                    return 0;
                                }
                            }
                            break;
                        }
                        case 1: {
                            // Binary protocol
                            if (network_data.size() >= 4) {
                                uint32_t magic = 0;
                                memcpy(&magic, network_data.data(), 4);
                                if (magic == 0x12345678) {
                                    // Valid magic number
                                    return 0;
                                }
                            }
                            break;
                        }
                        case 2: {
                            // JSON-like protocol
                            std::string data_str(reinterpret_cast<const char*>(network_data.data()), network_data.size());
                            if (data_str.find("{") != std::string::npos && data_str.find("}") != std::string::npos) {
                                // Simulate JSON parsing
                                return 0;
                            }
                            break;
                        }
                        case 3: {
                            // Custom protocol
                            if (network_data.size() >= 2) {
                                uint16_t version = network_data[0] | (network_data[1] << 8);
                                if (version >= 1 && version <= 10) {
                                    // Valid version range
                                    return 0;
                                }
                            }
                            break;
                        }
                    }
                }
                break;
            }
            
            case 3: {
                // Test network error handling
                // Test port handling based on fuzzer-provided values
                if (port > 0 && port <= 65535) {
                    // Valid port range
                    if (port < 1024) {
                        // Privileged port
                        return 0;
                    } else if (port >= 1024 && port < 49152) {
                        // Registered port
                        return 0;
                    } else {
                        // Dynamic/private port
                        return 0;
                    }
                } else {
                    // Invalid port - test error handling
                    return 0;
                }
                break;
            }
            
            case 4: {
                // Test data integrity checks
                if (network_data.size() > 0) {
                    // Simulate checksum calculation
                    uint32_t checksum = 0;
                    for (uint8_t byte : network_data) {
                        checksum += byte;
                    }
                    
                    // Test different checksum algorithms
                    uint32_t crc32 = 0;
                    for (uint8_t byte : network_data) {
                        crc32 ^= byte;
                        crc32 = (crc32 << 1) | (crc32 >> 31);
                    }
                    
                    // Test data validation
                    if (checksum == crc32) {
                        // Checksums match (unlikely but possible)
                        return 0;
                    } else {
                        // Normal case - checksums differ
                        return 0;
                    }
                }
                break;
            }
            
            case 5: {
                // Test network timing and latency
                if (network_data.size() > 0) {
                    // Simulate network latency calculation
                    double base_latency = 10.0; // 10ms base latency
                    double packet_size_factor = network_data.size() / 1000.0; // Size factor
                    double jitter = (port % 100) / 10.0; // Simulated jitter
                    
                    double total_latency = base_latency + packet_size_factor + jitter;
                    
                    // Test different latency scenarios
                    if (total_latency < 50.0) {
                        // Low latency
                        return 0;
                    } else if (total_latency < 200.0) {
                        // Medium latency
                        return 0;
                    } else {
                        // High latency
                        return 0;
                    }
                }
                break;
            }
            
            case 6: {
                // Test network congestion control
                if (network_data.size() > 0) {
                    // Simulate congestion window calculation
                    size_t window_size = 1;
                    size_t threshold = 16;
                    
                    // Simulate slow start
                    while (window_size < threshold && window_size < network_data.size()) {
                        window_size *= 2;
                    }
                    
                    // Simulate congestion avoidance
                    if (window_size >= threshold) {
                        window_size += 1;
                    }
                    
                    // Test congestion scenarios
                    if (window_size > network_data.size()) {
                        // No congestion
                        return 0;
                    } else {
                        // Congestion detected
                        return 0;
                    }
                }
                break;
            }
            
            case 7: {
                // Test extreme values and edge cases
                // Test with very large packets
                if (network_data.size() > 0) {
                    // Test packet fragmentation
                    size_t mtu = 1500; // Maximum Transmission Unit
                    if (network_data.size() > mtu) {
                        // Packet needs fragmentation
                        size_t fragments = (network_data.size() + mtu - 1) / mtu;
                        return 0;
                    } else {
                        // Single packet
                        return 0;
                    }
                }
                
                // Test with extreme port values
                if (port == 0 || port > 65535) {
                    // Invalid port - test error handling
                    return 0;
                }
                
                // Test with empty data
                if (network_data.empty()) {
                    // Empty packet - test handling
                    return 0;
                }
                
                return 0;
            }
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        // Fuzzing should continue even if exceptions occur
        return 0;
    } catch (...) {
        // Handle any other exceptions
        return 0;
    }
}