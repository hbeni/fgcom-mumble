#include <iostream>
#include <fstream>
#include <string>
#include <cstring>

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    
    std::ifstream file(argv[1]);
    if (!file) return 1;
    
    std::string input((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
    
    // Fuzz authentication functions
    if (input.find("admin") != std::string::npos) {
        // Simulate authentication
        return 0;
    }
    
    return 1;
}
