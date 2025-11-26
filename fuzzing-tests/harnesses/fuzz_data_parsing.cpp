#include <cstdint>
#include <cstddef>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <chrono>
#include <map>
#include <sstream>
#include <regex>

// Include FGCom data parsing headers
// #include "../../client/mumble-plugin/lib/config_parser.h"
// #include "../../client/mumble-plugin/lib/atis_parser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;
    
    FuzzedDataProvider fdp(Data, Size);
    
    try {
        // Timeout protection
        auto start = std::chrono::steady_clock::now();
        const auto timeout = std::chrono::seconds(20);
        
        // Extract parsing parameters
        uint8_t parse_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);
        std::string data = fdp.ConsumeRandomLengthString(8192);
        
        // Test JSON parsing
        if (parse_type == 0) { // JSON
            // Basic JSON structure validation
            if (data.empty()) {
                data = "{}";
            }
            
            // Add JSON structure if missing
            if (data.find('{') == std::string::npos && data.find('[') == std::string::npos) {
                data = "{\"data\":\"" + data + "\"}";
            }
            
            // Parse JSON-like structure
            std::map<std::string, std::string> json_data;
            size_t pos = 0;
            
            while (pos < data.size()) {
                size_t key_start = data.find('"', pos);
                if (key_start == std::string::npos) break;
                
                size_t key_end = data.find('"', key_start + 1);
                if (key_end == std::string::npos) break;
                
                std::string key = data.substr(key_start + 1, key_end - key_start - 1);
                
                size_t colon_pos = data.find(':', key_end);
                if (colon_pos == std::string::npos) break;
                
                size_t value_start = data.find('"', colon_pos);
                if (value_start == std::string::npos) break;
                
                size_t value_end = data.find('"', value_start + 1);
                if (value_end == std::string::npos) break;
                
                std::string value = data.substr(value_start + 1, value_end - value_start - 1);
                json_data[key] = value;
                
                pos = value_end + 1;
            }
            
            // Test JSON edge cases
            if (json_data.empty()) {
                // Try to parse as array
                if (data.find('[') != std::string::npos) {
                    std::vector<std::string> array_elements;
                    size_t array_start = data.find('[');
                    size_t array_end = data.find(']', array_start);
                    if (array_end != std::string::npos) {
                        std::string array_content = data.substr(array_start + 1, array_end - array_start - 1);
                        std::istringstream array_stream(array_content);
                        std::string element;
                        while (std::getline(array_stream, element, ',')) {
                            array_elements.push_back(element);
                        }
                    }
                }
            }
        }
        
        // Test XML parsing
        else if (parse_type == 1) { // XML
            // Add XML structure if missing
            if (data.find('<') == std::string::npos) {
                data = "<root>" + data + "</root>";
            }
            
            // Basic XML validation
            std::vector<std::string> tags;
            std::regex tag_regex("<([^>]+)>");
            std::sregex_iterator iter(data.begin(), data.end(), tag_regex);
            std::sregex_iterator end;
            
            for (; iter != end; ++iter) {
                std::string tag = (*iter)[1].str();
                tags.push_back(tag);
            }
            
            // Check for balanced tags
            std::vector<std::string> open_tags;
            for (const std::string& tag : tags) {
                if (tag[0] == '/') {
                    // Closing tag
                    std::string open_tag = tag.substr(1);
                    if (!open_tags.empty() && open_tags.back() == open_tag) {
                        open_tags.pop_back();
                    }
                } else {
                    // Opening tag
                    open_tags.push_back(tag);
                }
            }
            
            // Test XML attributes
            std::regex attr_regex("([a-zA-Z_][a-zA-Z0-9_]*)\\s*=\\s*\"([^\"]*)\"");
            std::sregex_iterator attr_iter(data.begin(), data.end(), attr_regex);
            std::sregex_iterator attr_end;
            
            std::map<std::string, std::string> attributes;
            for (; attr_iter != attr_end; ++attr_iter) {
                std::string attr_name = (*attr_iter)[1].str();
                std::string attr_value = (*attr_iter)[2].str();
                attributes[attr_name] = attr_value;
            }
        }
        
        // Test SQL query parsing
        else if (parse_type == 2) { // SQL
            // Basic SQL structure validation
            std::string sql_query = data;
            
            // Convert to uppercase for analysis
            std::transform(sql_query.begin(), sql_query.end(), sql_query.begin(), ::toupper);
            
            // Check for SQL injection patterns
            std::vector<std::string> dangerous_patterns = {
                "DROP TABLE",
                "DELETE FROM",
                "UPDATE SET",
                "INSERT INTO",
                "UNION SELECT",
                "OR 1=1",
                "AND 1=1",
                "'; --",
                "/*",
                "*/"
            };
            
            bool dangerous_query = false;
            for (const std::string& pattern : dangerous_patterns) {
                if (sql_query.find(pattern) != std::string::npos) {
                    dangerous_query = true;
                    break;
                }
            }
            
            // Parse SQL statement type
            std::string statement_type = "UNKNOWN";
            if (sql_query.find("SELECT") == 0) {
                statement_type = "SELECT";
            } else if (sql_query.find("INSERT") == 0) {
                statement_type = "INSERT";
            } else if (sql_query.find("UPDATE") == 0) {
                statement_type = "UPDATE";
            } else if (sql_query.find("DELETE") == 0) {
                statement_type = "DELETE";
            } else if (sql_query.find("CREATE") == 0) {
                statement_type = "CREATE";
            } else if (sql_query.find("DROP") == 0) {
                statement_type = "DROP";
            }
            
            // Extract table names
            std::vector<std::string> tables;
            std::regex table_regex("FROM\\s+([a-zA-Z_][a-zA-Z0-9_]*)");
            std::sregex_iterator table_iter(sql_query.begin(), sql_query.end(), table_regex);
            std::sregex_iterator table_end;
            
            for (; table_iter != table_end; ++table_iter) {
                std::string table_name = (*table_iter)[1].str();
                tables.push_back(table_name);
            }
        }
        
        // Test configuration file parsing
        else if (parse_type == 3) { // CONFIG
            // Parse key-value pairs
            std::map<std::string, std::string> config_data;
            std::istringstream config_stream(data);
            std::string line;
            
            while (std::getline(config_stream, line)) {
                // Remove comments
                size_t comment_pos = line.find('#');
                if (comment_pos != std::string::npos) {
                    line = line.substr(0, comment_pos);
                }
                
                // Find key-value separator
                size_t equal_pos = line.find('=');
                if (equal_pos != std::string::npos) {
                    std::string key = line.substr(0, equal_pos);
                    std::string value = line.substr(equal_pos + 1);
                    
                    // Trim whitespace
                    key.erase(0, key.find_first_not_of(" \t"));
                    key.erase(key.find_last_not_of(" \t") + 1);
                    value.erase(0, value.find_first_not_of(" \t"));
                    value.erase(value.find_last_not_of(" \t") + 1);
                    
                    if (!key.empty()) {
                        config_data[key] = value;
                    }
                }
            }
            
            // Test configuration validation
            for (const auto& pair : config_data) {
                const std::string& key = pair.first;
                const std::string& value = pair.second;
                
                // Check for valid key format
                if (key.empty() || key[0] == ' ') {
                    continue; // Invalid key
                }
                
                // Check for numeric values
                if (key.find("port") != std::string::npos || key.find("timeout") != std::string::npos) {
                    try {
                        int numeric_value = std::stoi(value);
                        if (numeric_value < 0 || numeric_value > 65535) {
                            // Invalid numeric value
                            continue;
                        }
                    } catch (const std::exception&) {
                        // Invalid numeric format
                        continue;
                    }
                }
            }
        }
        
        // Test ATIS message parsing
        else if (parse_type == 4) { // ATIS
            // ATIS message structure
            std::string atis_message = data;
            
            // Add ATIS structure if missing
            if (atis_message.find("ATIS") == std::string::npos) {
                atis_message = "ATIS " + atis_message;
            }
            
            // Parse ATIS components
            std::map<std::string, std::string> atis_data;
            
            // Extract airport code
            std::regex airport_regex("ATIS\\s+([A-Z]{3,4})");
            std::smatch airport_match;
            if (std::regex_search(atis_message, airport_match, airport_regex)) {
                atis_data["airport"] = airport_match[1].str();
            }
            
            // Extract wind information
            std::regex wind_regex("WIND\\s+(\\d{3})/(\\d{2,3})");
            std::smatch wind_match;
            if (std::regex_search(atis_message, wind_match, wind_regex)) {
                atis_data["wind_direction"] = wind_match[1].str();
                atis_data["wind_speed"] = wind_match[2].str();
            }
            
            // Extract visibility
            std::regex visibility_regex("VISIBILITY\\s+(\\d+)");
            std::smatch visibility_match;
            if (std::regex_search(atis_message, visibility_match, visibility_regex)) {
                atis_data["visibility"] = visibility_match[1].str();
            }
            
            // Extract temperature
            std::regex temp_regex("TEMP\\s+(\\d+)");
            std::smatch temp_match;
            if (std::regex_search(atis_message, temp_match, temp_regex)) {
                atis_data["temperature"] = temp_match[1].str();
            }
            
            // Extract pressure
            std::regex pressure_regex("PRESSURE\\s+(\\d{4})");
            std::smatch pressure_match;
            if (std::regex_search(atis_message, pressure_match, pressure_regex)) {
                atis_data["pressure"] = pressure_match[1].str();
            }
            
            // Validate ATIS data
            for (const auto& pair : atis_data) {
                const std::string& key = pair.first;
                const std::string& value = pair.second;
                
                if (key == "wind_direction") {
                    int direction = std::stoi(value);
                    if (direction < 0 || direction > 360) {
                        continue; // Invalid wind direction
                    }
                } else if (key == "wind_speed") {
                    int speed = std::stoi(value);
                    if (speed < 0 || speed > 200) {
                        continue; // Invalid wind speed
                    }
                } else if (key == "visibility") {
                    int vis = std::stoi(value);
                    if (vis < 0 || vis > 10000) {
                        continue; // Invalid visibility
                    }
                } else if (key == "temperature") {
                    int temp = std::stoi(value);
                    if (temp < -100 || temp > 100) {
                        continue; // Invalid temperature
                    }
                } else if (key == "pressure") {
                    int pressure = std::stoi(value);
                    if (pressure < 800 || pressure > 1200) {
                        continue; // Invalid pressure
                    }
                }
            }
        }
        
        // Test data format validation
        std::string format = fdp.ConsumeRandomLengthString(16);
        
        // Check for common data formats
        if (format.find("json") != std::string::npos || format.find("JSON") != std::string::npos) {
            // JSON format validation
            if (data.find('{') == std::string::npos && data.find('[') == std::string::npos) {
                return 0; // Invalid JSON
            }
        } else if (format.find("xml") != std::string::npos || format.find("XML") != std::string::npos) {
            // XML format validation
            if (data.find('<') == std::string::npos) {
                return 0; // Invalid XML
            }
        } else if (format.find("csv") != std::string::npos || format.find("CSV") != std::string::npos) {
            // CSV format validation
            if (data.find(',') == std::string::npos) {
                return 0; // Invalid CSV
            }
        }
        
        // Test data size limits
        if (data.size() > 1024 * 1024) { // 1MB limit
            return 0;
        }
        
        // Test encoding detection
        bool has_utf8 = false;
        bool has_ascii = true;
        for (char c : data) {
            if (static_cast<unsigned char>(c) > 127) {
                has_utf8 = true;
                has_ascii = false;
            }
        }
        
        // Timeout check
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > timeout) {
            return 0;
        }
        
    } catch (const std::exception& e) {
        return 0;
    } catch (...) {
        return 0;
    }
    
    return 0;
}
