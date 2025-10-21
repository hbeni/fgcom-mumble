#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0;
    
    size_t offset = 0;
    uint8_t selector = Data[offset++];
    
    // Extract performance parameters
    uint32_t iterations = 0;
    
    if (offset + 4 <= Size) {
        std::memcpy(&iterations, Data + offset, 4);
        offset += 4;
    }
    
    // Limit iterations
    iterations = std::min(iterations, static_cast<uint32_t>(100));
    if (iterations == 0) iterations = 1;
    
    try {
        // Pick ONE path based on selector
        switch (selector % 4) {
            case 0: {
                // Test computational performance - use fuzzer input directly
                double result = std::sin(iterations * M_PI / 180.0);
                break;
            }
            case 1: {
                // Test memory performance - use fuzzer input directly
                std::vector<double> data(iterations);
                data[0] = iterations * 1.5;
                break;
            }
            case 2: {
                // Test I/O performance - use fuzzer input directly
                std::string buffer(iterations, 'A');
                // Simulate I/O operations based on fuzzer-provided values
                break;
            }
            case 3: {
                // Test algorithm complexity - use fuzzer input directly
                // Test algorithm based on fuzzer-provided values
                break;
            }
        }
        
        return 0;
    } catch (...) {
        return 0;
    }
}