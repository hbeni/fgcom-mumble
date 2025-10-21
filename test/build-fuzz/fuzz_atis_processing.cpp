#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0;
    
    size_t offset = 0;
    uint8_t selector = Data[offset++];
    
    // Extract ATIS parameters
    uint32_t message_len = 0;
    
    if (offset + 4 <= Size) {
        std::memcpy(&message_len, Data + offset, 4);
        offset += 4;
    }
    
    // Limit message length
    message_len = std::min(message_len, static_cast<uint32_t>(Size - offset));
    if (message_len == 0) message_len = 1;
    
    try {
        // Extract ATIS message
        std::string atis_message(reinterpret_cast<const char*>(Data + offset), message_len);
        
        // Pick ONE path based on selector
        switch (selector % 4) {
            case 0: {
                // Test ATIS message parsing
                if (atis_message.find("ATIS") != std::string::npos) {
                    // Parse ATIS information
                }
                break;
            }
            case 1: {
                // Test weather data processing
                if (atis_message.find("WIND") != std::string::npos) {
                    // Process wind information
                }
                break;
            }
            case 2: {
                // Test runway information
                if (atis_message.find("RUNWAY") != std::string::npos) {
                    // Process runway data
                }
                break;
            }
            case 3: {
                // Test ATIS error handling
                if (atis_message.empty() || atis_message.length() > 1000) {
                    // Handle invalid ATIS message
                }
                break;
            }
        }
        
        return 0;
    } catch (...) {
        return 0;
    }
}
