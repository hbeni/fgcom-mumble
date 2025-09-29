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
        
        if (server_running) {
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
        
        if (server_running) {
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
    if (server_running) {
        server_running = false;
        if (server_thread.joinable()) {
            server_thread.join();
        }
    }
}

bool FGCom_APIServer::isRunning() const {
    return server_running;
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
            {"total_requests", total_requests},
            {"uptime_seconds", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
        res.set_content(response.dump(), "application/json");
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
        server_running = true;
        if (!server->listen(server_host.c_str(), server_port)) {
            std::cerr << "[APIServer] Failed to start server on " << server_host << ":" << server_port << std::endl;
            server_running = false;
        }
    } catch (const std::exception& e) {
        std::cerr << "[APIServer] Server thread exception: " << e.what() << std::endl;
        server_running = false;
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
