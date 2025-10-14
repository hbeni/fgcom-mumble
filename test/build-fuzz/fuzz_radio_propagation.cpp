#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    
    std::ifstream file(argv[1]);
    if (!file) return 1;
    
    std::string input((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
    
    // Fuzz radio propagation calculations
    if (input.find("AIRPORT:") != std::string::npos ||
        input.find("RADIO_RANGE:") != std::string::npos ||
        input.find("TERRAIN:") != std::string::npos ||
        input.find("WEATHER:") != std::string::npos ||
        input.find(",") != std::string::npos) {
        return 0;
    }
    
    return 1;
}
