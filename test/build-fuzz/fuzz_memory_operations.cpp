#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    
    std::ifstream file(argv[1]);
    if (!file) return 1;
    
    std::string input((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
    
    // Fuzz memory operations
    if (input.length() > 0) {
        return 0;
    }
    
    return 1;
}
