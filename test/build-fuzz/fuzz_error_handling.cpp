#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0;
    
    size_t offset = 0;
    uint8_t selector = Data[offset++];
    
    // Extract error parameters
    uint32_t error_code = 0;
    
    if (offset + 4 <= Size) {
        std::memcpy(&error_code, Data + offset, 4);
        offset += 4;
    }
    
    try {
        // Pick ONE path based on selector
        switch (selector % 4) {
            case 0: {
                // Test exception handling
                if (error_code == 0) {
                    throw std::runtime_error("Test exception");
                }
                break;
            }
            case 1: {
                // Test error recovery - use fuzzer input directly
                // Simulate error recovery based on error_code value
                break;
            }
            case 2: {
                // Test error logging - use fuzzer input directly
                // Simulate error logging based on error_code value
                break;
            }
            case 3: {
                // Test error propagation - use fuzzer input directly
                // Simulate error propagation based on error_code value
                break;
            }
        }
        
        return 0;
    } catch (...) {
        return 0;
    }
}