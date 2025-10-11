#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    
    std::ifstream file(argv[1]);
    if (!file) return 1;
    
    std::string input((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
    
    // Fuzz WebRTC operations
    if (input.find("WebRTC") != std::string::npos || 
        input.find("RTC") != std::string::npos) {
        return 0;
    }
    
    return 1;
}
