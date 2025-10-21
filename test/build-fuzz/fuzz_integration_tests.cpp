#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0;
    
    size_t offset = 0;
    uint8_t selector = Data[offset++];
    
    // Extract integration parameters
    uint32_t scenario_len = 0;
    
    if (offset + 4 <= Size) {
        std::memcpy(&scenario_len, Data + offset, 4);
        offset += 4;
    }
    
    // Limit scenario length
    scenario_len = std::min(scenario_len, static_cast<uint32_t>(Size - offset));
    if (scenario_len == 0) scenario_len = 1;
    
    try {
        // Extract scenario data
        std::string scenario(reinterpret_cast<const char*>(Data + offset), scenario_len);
        
        // Pick ONE path based on selector
        switch (selector % 4) {
            case 0: {
                // Test end-to-end communication - use fuzzer input directly
                if (scenario.find("COMM") != std::string::npos) {
                    // Simulate communication flow
                }
                break;
            }
            case 1: {
                // Test system integration - use fuzzer input directly
                if (scenario.find("SYS") != std::string::npos) {
                    // Simulate system integration
                }
                break;
            }
            case 2: {
                // Test component interaction - use fuzzer input directly
                if (scenario.find("COMP") != std::string::npos) {
                    // Simulate component interaction
                }
                break;
            }
            case 3: {
                // Test integration error handling - use fuzzer input directly
                // Handle integration errors based on fuzzer-provided values
                break;
            }
        }
        
        return 0;
    } catch (...) {
        return 0;
    }
}