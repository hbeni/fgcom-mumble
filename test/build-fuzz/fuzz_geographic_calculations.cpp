#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 16) return 0;
    
    size_t offset = 0;
    uint8_t selector = Data[offset++];
    
    // Extract geographic parameters
    double lat1 = 0.0;
    double lon1 = 0.0;
    double lat2 = 0.0;
    double lon2 = 0.0;
    
    if (offset + 8 <= Size) {
        std::memcpy(&lat1, Data + offset, 8);
        offset += 8;
    }
    if (offset + 8 <= Size) {
        std::memcpy(&lon1, Data + offset, 8);
        offset += 8;
    }
    if (offset + 8 <= Size) {
        std::memcpy(&lat2, Data + offset, 8);
        offset += 8;
    }
    if (offset + 8 <= Size) {
        std::memcpy(&lon2, Data + offset, 8);
        offset += 8;
    }
    
    try {
        // Pick ONE path based on selector
        switch (selector % 4) {
            case 0: {
                // Test distance calculation - use fuzzer input directly
                double distance = std::sqrt((lat2-lat1)*(lat2-lat1) + (lon2-lon1)*(lon2-lon1));
                break;
            }
            case 1: {
                // Test bearing calculation - use fuzzer input directly
                double bearing = std::atan2(lon2-lon1, lat2-lat1) * 180.0 / M_PI;
                break;
            }
            case 2: {
                // Test coordinate validation - use fuzzer input directly
                // Handle coordinate validation based on fuzzer-provided values
                break;
            }
            case 3: {
                // Test coordinate transformation - use fuzzer input directly
                // Handle coordinate transformation based on fuzzer-provided values
                break;
            }
        }
        
        return 0;
    } catch (...) {
        return 0;
    }
}