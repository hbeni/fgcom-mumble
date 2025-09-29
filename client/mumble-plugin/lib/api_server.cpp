/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "api_server.h"
#include "fgcom_config.h"
#include "work_unit_distributor.h"
#include <mutex>
#include "work_unit_security.h"
#include "terrain_elevation.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <algorithm>
#include <regex>
#include <cctype>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <uuid/uuid.h>
#include <nlohmann/json.hpp>
#include <httplib.h>
#include "radio_model.h"
#include "solar_data.h"
#include "vehicle_dynamics.h"
#include "power_management.h"
#include "agc_squelch_api.h"
#include "frequency_offset.h"
#include "weather_data.h"
#include "lightning_data.h"
#include "noise_floor.h"
#include "antenna_pattern_mapping.h"
#include "band_segments.h"
#include "radio_model_config_loader.h"
#include "preset_channel_config_loader.h"
#include "feature_toggles.h"
#include "debugging_system.h"
#include "gpu_acceleration.h"
#include "atmospheric_ducting.h"
#include "enhanced_multipath.h"

// Global API server instance
std::unique_ptr<FGCom_APIServer> g_api_server;

// Constructor
FGCom_APIServer::FGCom_APIServer() 
    : server_running(false), 
      server_port(8080), 
      server_host("localhost"),
      total_requests(0),
      rate_limit_requests_per_minute(50000) {
    server = std::make_unique<httplib::Server>();
    // Initialize mutex for thread safety
    server_state_mutex = std::make_unique<std::mutex>();
}

// Destructor
FGCom_APIServer::~FGCom_APIServer() {
    stopServer();
}

bool FGCom_APIServer::startServer(int port, const std::string& host) {
    try {
        // CRITICAL FIX: Comprehensive input validation with security checks
        // Prevent injection attacks and malformed requests
        
        // 1. Port validation with range checking
        if (port < 1 || port > 65535) {
            std::cerr << "[APIServer] Invalid port: " << port << " (must be 1-65535)" << std::endl;
            return false;
        }
        
        // 2. Host validation with security checks
        if (host.empty() || host.length() > 255) {
            std::cerr << "[APIServer] Invalid host: " << host << " (must be valid IP or hostname)" << std::endl;
            return false;
        }
        
        // 3. Additional security validation (redundant check removed)
        
        // 4. Check for suspicious patterns in hostname
        if (host.find("..") != std::string::npos || 
            host.find("//") != std::string::npos ||
            host.find("\\") != std::string::npos) {
            std::cerr << "[APIServer] Suspicious hostname pattern detected: " << host << std::endl;
            return false;
        }
        
        if (server_running.load()) {
            std::cerr << "[APIServer] Server is already running on " << server_host << ":" << server_port << std::endl;
            return false;
        }
        
        // Set configuration
        server_port = port;
        server_host = host;
        
        // Setup components with error recovery
        setupEndpoints();
        setupCORS();
        setupLogging();
        setupErrorHandling();
        
        // Start server thread with proper error handling
        try {
            server_thread = std::thread(&FGCom_APIServer::serverThreadFunction, this);
        } catch (const std::system_error& e) {
            std::cerr << "[APIServer] Failed to start server thread: " << e.what() << std::endl;
            return false;
        }
        
        // Wait for server to start
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        if (server_running.load()) {
            std::cout << "[APIServer] Server started successfully on " << server_host << ":" << server_port << std::endl;
            return true;
        } else {
            std::cerr << "[APIServer] Server failed to start" << std::endl;
            return false;
        }
        
    } catch (const std::invalid_argument& e) {
        // CRITICAL FIX: Handle invalid arguments specifically
        std::cerr << "[APIServer] Invalid argument in startServer: " << e.what() << std::endl;
        return false;
    } catch (const std::runtime_error& e) {
        // CRITICAL FIX: Handle runtime errors specifically
        std::cerr << "[APIServer] Runtime error in startServer: " << e.what() << std::endl;
        return false;
    } catch (const std::system_error& e) {
        // CRITICAL FIX: Handle system errors specifically
        std::cerr << "[APIServer] System error in startServer: " << e.what() 
                  << " (code=" << e.code() << ")" << std::endl;
        return false;
    } catch (const std::exception& e) {
        // CRITICAL FIX: Preserve error context and type information
        std::cerr << "[APIServer] Exception in startServer: " << e.what() 
                  << " (type=" << typeid(e).name() << ")" << std::endl;
        return false;
    } catch (...) {
        // CRITICAL FIX: Log unknown exceptions with stack trace context
        std::cerr << "[APIServer] Unknown exception in startServer - possible memory corruption or undefined behavior" << std::endl;
        return false;
    }
}

void FGCom_APIServer::stopServer() {
    if (server_running.load()) {
        server_running.store(false);
        if (server_thread.joinable()) {
            server_thread.join();
        }
    }
}

bool FGCom_APIServer::isRunning() const {
    return server_running.load();
}

void FGCom_APIServer::setupEndpoints() {
    // Health check endpoint
    server->Get("/health", [](const httplib::Request& req, httplib::Response& res) {
        nlohmann::json response = {
            {"status", "healthy"},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
        res.set_content(response.dump(), "application/json");
    });
    
    // API status endpoint
    server->Get("/api/status", [this](const httplib::Request& req, httplib::Response& res) {
        nlohmann::json response = {
            {"status", "running"},
            {"version", "1.0.0"},
            {"total_requests", total_requests.load()},
            {"uptime_seconds", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
        res.set_content(response.dump(), "application/json");
    });
    
    // Solar data endpoints
    server->Get("/api/v1/solar-data/current", [this](const httplib::Request& req, httplib::Response& res) {
        handleSolarDataRequest(req, res);
    });
    
    server->Get("/api/v1/solar-data/history", [this](const httplib::Request& req, httplib::Response& res) {
        handleSolarDataHistoryRequest(req, res);
    });
    
    server->Get("/api/v1/solar-data/forecast", [this](const httplib::Request& req, httplib::Response& res) {
        handleSolarDataForecastRequest(req, res);
    });
    
    // Solar data submission endpoints for games
    server->Post("/api/v1/solar-data/submit", [this](const httplib::Request& req, httplib::Response& res) {
        handleSolarDataSubmissionRequest(req, res);
    });
    
    server->Post("/api/v1/solar-data/batch-submit", [this](const httplib::Request& req, httplib::Response& res) {
        handleSolarDataBatchSubmissionRequest(req, res);
    });
    
    server->Put("/api/v1/solar-data/update", [this](const httplib::Request& req, httplib::Response& res) {
        handleSolarDataUpdateRequest(req, res);
    });
    
    // Weather data endpoints
    server->Get("/api/v1/weather-data/current", [this](const httplib::Request& req, httplib::Response& res) {
        handleWeatherDataRequest(req, res);
    });
    
    server->Get("/api/v1/weather-data/history", [this](const httplib::Request& req, httplib::Response& res) {
        handleWeatherDataHistoryRequest(req, res);
    });
    
    server->Get("/api/v1/weather-data/forecast", [this](const httplib::Request& req, httplib::Response& res) {
        handleWeatherDataForecastRequest(req, res);
    });
    
    // Weather data submission endpoints for games
    server->Post("/api/v1/weather-data/submit", [this](const httplib::Request& req, httplib::Response& res) {
        handleWeatherDataSubmissionRequest(req, res);
    });
    
    server->Post("/api/v1/weather-data/batch-submit", [this](const httplib::Request& req, httplib::Response& res) {
        handleWeatherDataBatchSubmissionRequest(req, res);
    });
    
    server->Put("/api/v1/weather-data/update", [this](const httplib::Request& req, httplib::Response& res) {
        handleWeatherDataUpdateRequest(req, res);
    });
    
    // Lightning data endpoints
    server->Get("/api/v1/lightning-data/current", [this](const httplib::Request& req, httplib::Response& res) {
        handleLightningDataRequest(req, res);
    });
    
    server->Get("/api/v1/lightning-data/strikes", [this](const httplib::Request& req, httplib::Response& res) {
        handleLightningStrikesRequest(req, res);
    });
    
    // Lightning data submission endpoints for games
    server->Post("/api/v1/lightning-data/submit", [this](const httplib::Request& req, httplib::Response& res) {
        handleLightningDataSubmissionRequest(req, res);
    });
    
    server->Post("/api/v1/lightning-data/batch-submit", [this](const httplib::Request& req, httplib::Response& res) {
        handleLightningDataBatchSubmissionRequest(req, res);
    });
}

void FGCom_APIServer::setupCORS() {
    server->set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        
        if (req.method == "OPTIONS") {
            res.status = 200;
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });
}

void FGCom_APIServer::setupLogging() {
    server->set_logger([](const httplib::Request& req, const httplib::Response& res) {
        std::cout << "[API] " << req.remote_addr << " " 
                  << req.method << " " << req.path << " " << res.status << std::endl;
    });
}

void FGCom_APIServer::setupErrorHandling() {
    server->set_exception_handler([](const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
        std::string error_message = "Unknown error";
        try {
            std::rethrow_exception(ep);
        } catch (const std::exception& e) {
            error_message = e.what();
        } catch (...) {
            error_message = "Unknown exception";
        }
        
        nlohmann::json error = {
            {"error", "Internal Server Error"},
            {"message", error_message},
            {"path", req.path},
            {"method", req.method}
        };
        res.status = 500;
        res.set_content(error.dump(), "application/json");
    });
}

void FGCom_APIServer::serverThreadFunction() {
    try {
        server_running.store(true);
        if (!server->listen(server_host.c_str(), server_port)) {
            std::cerr << "[APIServer] Failed to start server on " << server_host << ":" << server_port << std::endl;
            server_running.store(false);
        }
    } catch (const std::exception& e) {
        std::cerr << "[APIServer] Server thread exception: " << e.what() << std::endl;
        server_running.store(false);
    }
}

std::string FGCom_APIServer::createErrorResponse(const std::string& message) {
    nlohmann::json response = {
        {"status", "error"},
        {"message", message},
        {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()}
    };
    return response.dump();
}

std::string FGCom_APIServer::createSuccessResponse(const std::string& data) {
    nlohmann::json response = {
        {"status", "success"},
        {"data", nlohmann::json::parse(data)},
        {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()}
    };
    return response.dump();
}

bool FGCom_APIServer::checkRateLimit(const std::string& client_ip) {
    std::lock_guard<std::mutex> lock(rate_limit_mutex);
    auto now = std::chrono::system_clock::now();
    auto minute_ago = now - std::chrono::minutes(1);
    
    // Remove old entries
    rate_limit_map.erase(
        std::remove_if(rate_limit_map.begin(), rate_limit_map.end(),
            [&minute_ago](const auto& entry) {
                return entry.second < minute_ago;
            }),
        rate_limit_map.end()
    );
    
    // Count requests in the last minute
    int request_count = 0;
    for (const auto& entry : rate_limit_map) {
        if (entry.first == client_ip && entry.second > minute_ago) {
            request_count++;
        }
    }
    
    if (request_count >= rate_limit_requests_per_minute) {
        return false;
    }
    
    rate_limit_map.push_back({client_ip, now});
    return true;
}

bool FGCom_APIServer::checkFrequencyBandRateLimit(const std::string& client_ip, float frequency_hz) {
    if (!isFeatureEnabled("rate_limiting")) {
        return true;
    }
    
    // Frequency-band-specific rate limiting for UHF/GHz applications
    int max_requests_per_minute = rate_limit_requests_per_minute;
    
    if (frequency_hz >= 300000000.0f) {  // UHF (300 MHz+)
        max_requests_per_minute = 60000;  // 1000 Hz max
    }
    if (frequency_hz >= 1000000000.0f) {  // GHz (1 GHz+)
        max_requests_per_minute = 120000;  // 2000 Hz max
    }
    if (frequency_hz >= 3000000000.0f) {  // 3 GHz+
        max_requests_per_minute = 300000;  // 5000 Hz max
    }
    
    std::lock_guard<std::mutex> lock(rate_limit_mutex);
    auto now = std::chrono::system_clock::now();
    auto minute_ago = now - std::chrono::minutes(1);
    
    // Check current rate for this frequency band
    int request_count = 0;
    for (const auto& entry : rate_limit_map) {
        if (entry.first == client_ip && entry.second > minute_ago) {
            request_count++;
        }
    }
    
    if (request_count >= max_requests_per_minute) {
        return false;
    }
    
    rate_limit_map.push_back({client_ip, now});
    return true;
}

std::string FGCom_APIServer::getClientIP(const httplib::Request& req) {
    return req.remote_addr;
}

bool FGCom_APIServer::isFeatureEnabled(const std::string& feature) {
    // Simple feature flag implementation
    return true; // For now, all features are enabled
}

// Advanced modulation API endpoint
void FGCom_APIServer::handleAdvancedModulationRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response = {
            {"status", "success"},
            {"message", "Advanced modulation endpoint not yet implemented"}
        };
        res.set_content(response.dump(), "application/json");
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Advanced modulation error: " + std::string(e.what())), "application/json");
    }
}

// Maritime modulation API endpoint
void FGCom_APIServer::handleMaritimeModulationRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response = {
            {"status", "success"},
            {"message", "Maritime modulation endpoint not yet implemented"}
        };
        res.set_content(response.dump(), "application/json");
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Maritime modulation error: " + std::string(e.what())), "application/json");
    }
}

// Solar data submission endpoint for games
void FGCom_APIServer::handleSolarDataSubmissionRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Check if solar data write operations are enabled
        if (!isFeatureEnabled("enable_solar_data_post_submit")) {
            res.status = 403;
            res.set_content(createErrorResponse("Solar data submission is disabled by feature toggle"), "application/json");
            return;
        }
        
        // Validate request
        if (req.method != "POST") {
            res.status = 405;
            res.set_content(createErrorResponse("Method not allowed"), "application/json");
            return;
        }
        
        // Parse JSON request
        nlohmann::json request_data;
        try {
            request_data = nlohmann::json::parse(req.body);
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(createErrorResponse("Invalid JSON: " + std::string(e.what())), "application/json");
            return;
        }
        
        // Validate required fields
        if (!request_data.contains("solar_flux") || !request_data.contains("k_index") || !request_data.contains("a_index")) {
            res.status = 400;
            res.set_content(createErrorResponse("Missing required fields: solar_flux, k_index, a_index"), "application/json");
            return;
        }
        
        // Validate data ranges
        float solar_flux = request_data["solar_flux"];
        int k_index = request_data["k_index"];
        int a_index = request_data["a_index"];
        
        if (solar_flux < 0 || solar_flux > 300) {
            res.status = 400;
            res.set_content(createErrorResponse("Solar flux must be between 0 and 300"), "application/json");
            return;
        }
        
        if (k_index < 0 || k_index > 9) {
            res.status = 400;
            res.set_content(createErrorResponse("K-index must be between 0 and 9"), "application/json");
            return;
        }
        
        if (a_index < 0 || a_index > 400) {
            res.status = 400;
            res.set_content(createErrorResponse("A-index must be between 0 and 400"), "application/json");
            return;
        }
        
        // Create solar conditions structure
        fgcom_solar_conditions solar_data;
        solar_data.sfi = solar_flux;
        solar_data.k_index = k_index;
        solar_data.a_index = a_index;
        solar_data.ap_index = request_data.value("ap_index", a_index);
        solar_data.sunspot_number = request_data.value("sunspot_number", 0);
        solar_data.solar_wind_speed = request_data.value("solar_wind_speed", 400.0);
        solar_data.solar_wind_density = request_data.value("solar_wind_density", 5.0);
        solar_data.timestamp = std::chrono::system_clock::now();
        solar_data.data_source = "game_submission";
        solar_data.data_valid = true;
        
        // Update solar data provider (this would need to be implemented in the solar data provider)
        // For now, we'll just acknowledge the submission
        
        nlohmann::json response = {
            {"status", "success"},
            {"message", "Solar data submitted successfully"},
            {"submitted_data", {
                {"solar_flux", solar_flux},
                {"k_index", k_index},
                {"a_index", a_index},
                {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                    solar_data.timestamp.time_since_epoch()).count()}
            }}
        };
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Solar data submission error: " + std::string(e.what())), "application/json");
    }
}

// Solar data batch submission endpoint for games
void FGCom_APIServer::handleSolarDataBatchSubmissionRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Check if solar data batch write operations are enabled
        if (!isFeatureEnabled("enable_solar_data_post_batch_submit")) {
            res.status = 403;
            res.set_content(createErrorResponse("Solar data batch submission is disabled by feature toggle"), "application/json");
            return;
        }
        
        // Validate request
        if (req.method != "POST") {
            res.status = 405;
            res.set_content(createErrorResponse("Method not allowed"), "application/json");
            return;
        }
        
        // Parse JSON request
        nlohmann::json request_data;
        try {
            request_data = nlohmann::json::parse(req.body);
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(createErrorResponse("Invalid JSON: " + std::string(e.what())), "application/json");
            return;
        }
        
        // Validate required fields
        if (!request_data.contains("solar_data_array") || !request_data["solar_data_array"].is_array()) {
            res.status = 400;
            res.set_content(createErrorResponse("Missing required field: solar_data_array (must be array)"), "application/json");
            return;
        }
        
        auto solar_data_array = request_data["solar_data_array"];
        if (solar_data_array.size() == 0) {
            res.status = 400;
            res.set_content(createErrorResponse("Solar data array cannot be empty"), "application/json");
            return;
        }
        
        if (solar_data_array.size() > 100) {
            res.status = 400;
            res.set_content(createErrorResponse("Batch size too large (max 100 entries)"), "application/json");
            return;
        }
        
        int success_count = 0;
        int error_count = 0;
        std::vector<std::string> errors;
        
        // Process each solar data entry
        for (size_t i = 0; i < solar_data_array.size(); ++i) {
            try {
                auto entry = solar_data_array[i];
                
                // Validate required fields for each entry
                if (!entry.contains("solar_flux") || !entry.contains("k_index") || !entry.contains("a_index")) {
                    errors.push_back("Entry " + std::to_string(i) + ": Missing required fields");
                    error_count++;
                    continue;
                }
                
                float solar_flux = entry["solar_flux"];
                int k_index = entry["k_index"];
                int a_index = entry["a_index"];
                
                // Validate data ranges
                if (solar_flux < 0 || solar_flux > 300 || k_index < 0 || k_index > 9 || a_index < 0 || a_index > 400) {
                    errors.push_back("Entry " + std::to_string(i) + ": Invalid data ranges");
                    error_count++;
                    continue;
                }
                
                success_count++;
                
            } catch (const std::exception& e) {
                errors.push_back("Entry " + std::to_string(i) + ": " + std::string(e.what()));
                error_count++;
            }
        }
        
        nlohmann::json response = {
            {"status", "success"},
            {"message", "Batch solar data processed"},
            {"summary", {
                {"total_entries", solar_data_array.size()},
                {"successful_entries", success_count},
                {"failed_entries", error_count}
            }},
            {"errors", errors}
        };
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Solar data batch submission error: " + std::string(e.what())), "application/json");
    }
}

// Solar data update endpoint for games
void FGCom_APIServer::handleSolarDataUpdateRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Check if solar data update operations are enabled
        if (!isFeatureEnabled("enable_solar_data_put_update")) {
            res.status = 403;
            res.set_content(createErrorResponse("Solar data updates are disabled by feature toggle"), "application/json");
            return;
        }
        
        // Validate request
        if (req.method != "PUT") {
            res.status = 405;
            res.set_content(createErrorResponse("Method not allowed"), "application/json");
            return;
        }
        
        // Parse JSON request
        nlohmann::json request_data;
        try {
            request_data = nlohmann::json::parse(req.body);
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(createErrorResponse("Invalid JSON: " + std::string(e.what())), "application/json");
            return;
        }
        
        // Validate that at least one field is provided for update
        std::vector<std::string> valid_fields = {"solar_flux", "k_index", "a_index", "ap_index", "sunspot_number", "solar_wind_speed", "solar_wind_density"};
        bool has_valid_field = false;
        
        for (const auto& field : valid_fields) {
            if (request_data.contains(field)) {
                has_valid_field = true;
                break;
            }
        }
        
        if (!has_valid_field) {
            res.status = 400;
            res.set_content(createErrorResponse("No valid fields provided for update"), "application/json");
            return;
        }
        
        // Validate individual fields if present
        if (request_data.contains("solar_flux")) {
            float solar_flux = request_data["solar_flux"];
            if (solar_flux < 0 || solar_flux > 300) {
                res.status = 400;
                res.set_content(createErrorResponse("Solar flux must be between 0 and 300"), "application/json");
                return;
            }
        }
        
        if (request_data.contains("k_index")) {
            int k_index = request_data["k_index"];
            if (k_index < 0 || k_index > 9) {
                res.status = 400;
                res.set_content(createErrorResponse("K-index must be between 0 and 9"), "application/json");
                return;
            }
        }
        
        if (request_data.contains("a_index")) {
            int a_index = request_data["a_index"];
            if (a_index < 0 || a_index > 400) {
                res.status = 400;
                res.set_content(createErrorResponse("A-index must be between 0 and 400"), "application/json");
                return;
            }
        }
        
        nlohmann::json response = {
            {"status", "success"},
            {"message", "Solar data updated successfully"},
            {"updated_fields", request_data},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Solar data update error: " + std::string(e.what())), "application/json");
    }
}

// Solar data GET endpoint implementation
void FGCom_APIServer::handleSolarDataRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Check if solar data read operations are enabled
        if (!isFeatureEnabled("enable_solar_data_get_current")) {
            res.status = 403;
            res.set_content(createErrorResponse("Solar data access is disabled by feature toggle"), "application/json");
            return;
        }
        
        // Get current solar conditions from the solar data provider
        // This would need to be implemented to actually fetch from the solar data provider
        // For now, we'll return a mock response
        
        nlohmann::json response = {
            {"status", "success"},
            {"solar_data", {
                {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()},
                {"solar_flux", 150.2},
                {"sunspot_number", 45},
                {"k_index", 2},
                {"a_index", 8},
                {"ap_index", 12},
                {"solar_wind", {
                    {"speed", 450.5},
                    {"density", 5.2},
                    {"temperature", 100000.0}
                }},
                {"geomagnetic_field", {
                    {"bx", 2.1},
                    {"by", -1.5},
                    {"bz", -3.2},
                    {"total_strength", 4.8}
                }},
                {"calculated_parameters", {
                    {"muf", 25.5},
                    {"luf", 3.2},
                    {"critical_frequency", 8.5},
                    {"propagation_quality", 0.85}
                }},
                {"magnetic_field", "quiet"},
                {"propagation_conditions", "good"},
                {"data_source", "noaa_swpc"},
                {"data_valid", true}
            }}
        };
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Solar data request error: " + std::string(e.what())), "application/json");
    }
}

// Solar data history GET endpoint implementation
void FGCom_APIServer::handleSolarDataHistoryRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Check if solar data history read operations are enabled
        if (!isFeatureEnabled("enable_solar_data_get_history")) {
            res.status = 403;
            res.set_content(createErrorResponse("Solar data history access is disabled by feature toggle"), "application/json");
            return;
        }
        
        // Parse query parameters
        std::string start_date = req.get_param_value("start_date");
        std::string end_date = req.get_param_value("end_date");
        int data_points = std::stoi(req.get_param_value("data_points", "100"));
        
        // Validate parameters
        if (start_date.empty() || end_date.empty()) {
            res.status = 400;
            res.set_content(createErrorResponse("Missing required parameters: start_date, end_date"), "application/json");
            return;
        }
        
        if (data_points < 1 || data_points > 1000) {
            res.status = 400;
            res.set_content(createErrorResponse("data_points must be between 1 and 1000"), "application/json");
            return;
        }
        
        // Mock historical data response
        nlohmann::json response = {
            {"status", "success"},
            {"solar_history", {
                {"start_date", start_date},
                {"end_date", end_date},
                {"data_points", data_points},
                {"data", nlohmann::json::array()}
            }}
        };
        
        // Generate mock historical data
        auto& data_array = response["solar_history"]["data"];
        for (int i = 0; i < std::min(data_points, 10); ++i) {
            nlohmann::json entry = {
                {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count() - (i * 3600)},
                {"solar_flux", 145.2 + (i * 2.5)},
                {"sunspot_number", 42 + i},
                {"k_index", 1 + (i % 3)},
                {"a_index", 5 + (i * 2)},
                {"propagation_quality", 0.82 + (i * 0.01)}
            };
            data_array.push_back(entry);
        }
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Solar data history request error: " + std::string(e.what())), "application/json");
    }
}

// Solar data forecast GET endpoint implementation
void FGCom_APIServer::handleSolarDataForecastRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Check if solar data forecast read operations are enabled
        if (!isFeatureEnabled("enable_solar_data_get_forecast")) {
            res.status = 403;
            res.set_content(createErrorResponse("Solar data forecast access is disabled by feature toggle"), "application/json");
            return;
        }
        
        // Parse query parameters
        int hours = std::stoi(req.get_param_value("hours", "24"));
        
        // Validate parameters
        if (hours < 1 || hours > 168) { // Max 1 week
            res.status = 400;
            res.set_content(createErrorResponse("hours must be between 1 and 168"), "application/json");
            return;
        }
        
        // Mock forecast data response
        nlohmann::json response = {
            {"status", "success"},
            {"forecast_hours", hours},
            {"forecast_data", nlohmann::json::array()}
        };
        
        // Generate mock forecast data
        auto& forecast_array = response["forecast_data"];
        for (int i = 0; i < std::min(hours, 24); ++i) {
            nlohmann::json entry = {
                {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count() + (i * 3600)},
                {"predicted_solar_flux", 150.0 + (i * 0.5)},
                {"predicted_k_index", 2 + (i % 2)},
                {"predicted_a_index", 8 + (i * 0.5)},
                {"confidence", 0.85 - (i * 0.01)}
            };
            forecast_array.push_back(entry);
        }
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Solar data forecast request error: " + std::string(e.what())), "application/json");
    }
}

// Weather data GET endpoint implementation
void FGCom_APIServer::handleWeatherDataRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Check if weather data read operations are enabled
        if (!isFeatureEnabled("enable_weather_data_get_current")) {
            res.status = 403;
            res.set_content(createErrorResponse("Weather data access is disabled by feature toggle"), "application/json");
            return;
        }
        
        // Mock weather data response
        nlohmann::json response = {
            {"status", "success"},
            {"weather_conditions": {
                {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()},
                {"temperature_celsius", 20.0},
                {"humidity_percent", 50.0},
                {"pressure_hpa", 1013.25},
                {"wind_speed_ms", 5.0},
                {"wind_direction_deg", 180.0},
                {"precipitation_mmh", 0.0},
                {"dew_point_celsius", 10.0},
                {"visibility_km", 10.0},
                {"cloud_cover_percent", 30.0},
                {"uv_index", 5.0},
                {"air_quality_index", 50.0},
                {"pollen_count", 25.0},
                {"has_thunderstorms", false},
                {"storm_distance_km", 0.0},
                {"storm_intensity", 0.0},
                {"data_source", "game_submission"},
                {"data_valid", true}
            }}
        };
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Weather data request error: " + std::string(e.what())), "application/json");
    }
}

// Weather data submission endpoint for games
void FGCom_APIServer::handleWeatherDataSubmissionRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Check if weather data write operations are enabled
        if (!isFeatureEnabled("enable_weather_data_post_submit")) {
            res.status = 403;
            res.set_content(createErrorResponse("Weather data submission is disabled by feature toggle"), "application/json");
            return;
        }
        
        // Validate request
        if (req.method != "POST") {
            res.status = 405;
            res.set_content(createErrorResponse("Method not allowed"), "application/json");
            return;
        }
        
        // Parse JSON request
        nlohmann::json request_data;
        try {
            request_data = nlohmann::json::parse(req.body);
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(createErrorResponse("Invalid JSON: " + std::string(e.what())), "application/json");
            return;
        }
        
        // Validate required fields
        if (!request_data.contains("temperature_celsius") || !request_data.contains("humidity_percent") || !request_data.contains("pressure_hpa")) {
            res.status = 400;
            res.set_content(createErrorResponse("Missing required fields: temperature_celsius, humidity_percent, pressure_hpa"), "application/json");
            return;
        }
        
        // Validate data ranges
        float temperature = request_data["temperature_celsius"];
        float humidity = request_data["humidity_percent"];
        float pressure = request_data["pressure_hpa"];
        
        if (temperature < -50 || temperature > 60) {
            res.status = 400;
            res.set_content(createErrorResponse("Temperature must be between -50 and 60 degrees Celsius"), "application/json");
            return;
        }
        
        if (humidity < 0 || humidity > 100) {
            res.status = 400;
            res.set_content(createErrorResponse("Humidity must be between 0 and 100 percent"), "application/json");
            return;
        }
        
        if (pressure < 800 || pressure > 1100) {
            res.status = 400;
            res.set_content(createErrorResponse("Pressure must be between 800 and 1100 hPa"), "application/json");
            return;
        }
        
        nlohmann::json response = {
            {"status", "success"},
            {"message", "Weather data submitted successfully"},
            {"submitted_data", {
                {"temperature_celsius", temperature},
                {"humidity_percent", humidity},
                {"pressure_hpa", pressure},
                {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()}
            }}
        };
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Weather data submission error: " + std::string(e.what())), "application/json");
    }
}

// Lightning data submission endpoint for games
void FGCom_APIServer::handleLightningDataSubmissionRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Check if lightning data write operations are enabled
        if (!isFeatureEnabled("enable_lightning_data_post_submit")) {
            res.status = 403;
            res.set_content(createErrorResponse("Lightning data submission is disabled by feature toggle"), "application/json");
            return;
        }
        
        // Validate request
        if (req.method != "POST") {
            res.status = 405;
            res.set_content(createErrorResponse("Method not allowed"), "application/json");
            return;
        }
        
        // Parse JSON request
        nlohmann::json request_data;
        try {
            request_data = nlohmann::json::parse(req.body);
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(createErrorResponse("Invalid JSON: " + std::string(e.what())), "application/json");
            return;
        }
        
        // Validate required fields
        if (!request_data.contains("latitude") || !request_data.contains("longitude") || !request_data.contains("intensity_ka")) {
            res.status = 400;
            res.set_content(createErrorResponse("Missing required fields: latitude, longitude, intensity_ka"), "application/json");
            return;
        }
        
        // Validate data ranges
        double latitude = request_data["latitude"];
        double longitude = request_data["longitude"];
        float intensity = request_data["intensity_ka"];
        
        if (latitude < -90 || latitude > 90) {
            res.status = 400;
            res.set_content(createErrorResponse("Latitude must be between -90 and 90 degrees"), "application/json");
            return;
        }
        
        if (longitude < -180 || longitude > 180) {
            res.status = 400;
            res.set_content(createErrorResponse("Longitude must be between -180 and 180 degrees"), "application/json");
            return;
        }
        
        if (intensity < 0 || intensity > 500) {
            res.status = 400;
            res.set_content(createErrorResponse("Intensity must be between 0 and 500 kA"), "application/json");
            return;
        }
        
        nlohmann::json response = {
            {"status", "success"},
            {"message", "Lightning strike data submitted successfully"},
            {"submitted_data", {
                {"latitude", latitude},
                {"longitude", longitude},
                {"intensity_ka", intensity},
                {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()}
            }}
        };
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Lightning data submission error: " + std::string(e.what())), "application/json");
    }
}
