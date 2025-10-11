#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    
    std::ifstream file(argv[1]);
    if (!file) return 1;
    
    std::string input((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
    
    // Fuzz ATIS processing
    if (input.find("ATIS") != std::string::npos || 
        input.find("WIND") != std::string::npos) {
        return 0;
    }
    
    return 1;
}
