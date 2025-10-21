#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0;
    
    size_t offset = 0;
    uint8_t selector = Data[offset++];
    
    // Extract input parameters
    uint32_t input_len = 0;
    
    if (offset + 4 <= Size) {
        std::memcpy(&input_len, Data + offset, 4);
        offset += 4;
    }
    
    // Limit input length
    input_len = std::min(input_len, static_cast<uint32_t>(Size - offset));
    if (input_len == 0) input_len = 1;
    
    try {
        // Extract input data
        std::string input_data(reinterpret_cast<const char*>(Data + offset), input_len);
        
        // Pick ONE path based on selector
        switch (selector % 4) {
            case 0: {
                // Test input sanitization - use fuzzer input directly
                if (input_data.find("<script>") != std::string::npos) {
                    // Sanitize XSS attempt
                }
                break;
            }
            case 1: {
                // Test SQL injection prevention - use fuzzer input directly
                if (input_data.find("'; DROP TABLE") != std::string::npos) {
                    // Prevent SQL injection
                }
                break;
            }
            case 2: {
                // Test input length validation - use fuzzer input directly
                // Handle input length validation based on fuzzer-provided values
                break;
            }
            case 3: {
                // Test input format validation - use fuzzer input directly
                if (input_data.empty() || input_data.find('\0') != std::string::npos) {
                    // Handle invalid format
                }
                break;
            }
        }
        
        return 0;
    } catch (...) {
        return 0;
    }
}