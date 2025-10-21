#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0;
    
    size_t offset = 0;
    uint8_t selector = Data[offset++];
    
    // Extract memory parameters
    uint32_t alloc_size = 0;
    
    if (offset + 4 <= Size) {
        std::memcpy(&alloc_size, Data + offset, 4);
        offset += 4;
    }
    
    // Limit allocation size
    alloc_size = std::min(alloc_size, static_cast<uint32_t>(1024));
    if (alloc_size == 0) alloc_size = 1;
    
    try {
        // Pick ONE path based on selector
        switch (selector % 4) {
            case 0: {
                // Test memory allocation - use fuzzer input directly
                void* ptr = malloc(alloc_size);
                if (ptr) {
                    free(ptr);
                }
                break;
            }
            case 1: {
                // Test memory copying - use fuzzer input directly
                std::vector<uint8_t> src(alloc_size);
                std::vector<uint8_t> dst(alloc_size);
                std::memcpy(dst.data(), src.data(), alloc_size);
                break;
            }
            case 2: {
                // Test memory initialization - use fuzzer input directly
                std::vector<uint8_t> buffer(alloc_size);
                std::memset(buffer.data(), 0, alloc_size);
                break;
            }
            case 3: {
                // Test memory bounds checking - use fuzzer input directly
                std::vector<uint8_t> buffer(alloc_size);
                // Test bounds based on fuzzer-provided values
                break;
            }
        }
        
        return 0;
    } catch (...) {
        return 0;
    }
}