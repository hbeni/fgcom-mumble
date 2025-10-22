#include "atis_functions.h"
#include <iostream>

int main() {
    std::string airport_code = "KJFK";
    std::string weather_info = generateWeatherInfo();
    std::string runway_info = generateRunwayInfo();
    
    std::string atis_content = generateATISContent(airport_code, weather_info, runway_info);
    
    std::cout << "Generated ATIS content:" << std::endl;
    std::cout << atis_content << std::endl;
    std::cout << "Contains 'Advise you have information': " << (atis_content.find("Advise you have information") != std::string::npos) << std::endl;
    
    return 0;
}
