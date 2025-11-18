#include "systems/freedv/include/freedv.h"
#include "systems/melpe/include/melpe.h"
#include <iostream>
#include <vector>

int main() {
    std::cout << "Testing FreeDV and MELPe Systems" << std::endl;
    
    // Test FreeDV
    std::cout << "\n=== Testing FreeDV ===" << std::endl;
    fgcom::freedv::FreeDV freedv;
    
    if (!freedv.initialize(8000.0f, 1)) {
        std::cerr << "✗ FreeDV initialization failed" << std::endl;
        return 1;
    }
    
    std::cout << "✓ FreeDV initialized successfully" << std::endl;
    
    // Test FreeDV processing
    std::vector<float> test_audio = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};
    std::vector<float> processed = freedv.process(test_audio);
    
    if (processed.empty()) {
        std::cerr << "✗ FreeDV processing failed" << std::endl;
        return 1;
    }
    
    std::cout << "✓ FreeDV processing successful" << std::endl;
    
    // Test FreeDV encoding/decoding
    std::vector<uint8_t> encoded = freedv.encode(test_audio);
    if (encoded.empty()) {
        std::cerr << "✗ FreeDV encoding failed" << std::endl;
        return 1;
    }
    
    std::cout << "✓ FreeDV encoding successful" << std::endl;
    
    std::vector<float> decoded = freedv.decode(encoded);
    if (decoded.empty()) {
        std::cerr << "✗ FreeDV decoding failed" << std::endl;
        return 1;
    }
    
    std::cout << "✓ FreeDV decoding successful" << std::endl;
    
    // Test MELPe
    std::cout << "\n=== Testing MELPe ===" << std::endl;
    fgcom::melpe::MELPe melpe;
    
    if (!melpe.initialize(8000.0f, 1)) {
        std::cerr << "✗ MELPe initialization failed" << std::endl;
        return 1;
    }
    
    std::cout << "✓ MELPe initialized successfully" << std::endl;
    
    // Test MELPe processing
    std::vector<float> melpe_processed = melpe.process(test_audio);
    
    if (melpe_processed.empty()) {
        std::cerr << "✗ MELPe processing failed" << std::endl;
        return 1;
    }
    
    std::cout << "✓ MELPe processing successful" << std::endl;
    
    std::cout << "\n✓ All FreeDV and MELPe tests passed!" << std::endl;
    return 0;
}
