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
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <random>
#include <regex>
#include <cctype>
#include <limits>
#include <stdexcept>
#include <cassert>

// Static member definitions
std::unique_ptr<FGCom_Config> FGCom_Config::instance = nullptr;
std::mutex FGCom_Config::instance_mutex;

// API Server Implementation
FGCom_APIServer::FGCom_APIServer() 
    : server_running(false), websocket_enabled(false), server_port(8080), 
      server_host("0.0.0.0"), next_client_id(1), total_requests(0), 
      total_websocket_connections(0), rate_limit_requests_per_minute(100) {
    
    server = std::make_unique<httplib::Server>();
    server_start_time = std::chrono::system_clock::now();
    
    // Set default feature flags
    feature_flags["propagation"] = true;
    feature_flags["solar_data"] = true;
    feature_flags["band_status"] = true;
    feature_flags["antenna_patterns"] = true;
    feature_flags["ground_systems"] = true;
    feature_flags["gpu_status"] = true;
    feature_flags["websocket"] = true;
    feature_flags["rate_limiting"] = true;
    feature_flags["cors"] = true;
    
    // Set default API config
    api_config["version"] = "1.0.0";
    api_config["title"] = "FGCom-mumble API";
    api_config["description"] = "Radio propagation and amateur radio API";
    api_config["contact"] = "https://github.com/hbeni/fgcom-mumble";
}

FGCom_APIServer::~FGCom_APIServer() {
    stopServer();
}

bool FGCom_APIServer::startServer(int port, const std::string& host) {
    try {
        // Validate input parameters
        if (!validatePort(port)) {
            std::cerr << "[APIServer] Invalid port: " << port << std::endl;
            return false;
        }
        
        if (!validateHost(host)) {
            std::cerr << "[APIServer] Invalid host: " << host << std::endl;
            return false;
        }
        
        if (server_running) {
            std::cerr << "[APIServer] Server is already running" << std::endl;
            return false;
        }
        
        server_port = port;
        server_host = host;
        
        setupEndpoints();
        setupCORS();
        setupLogging();
        setupErrorHandling();
        
        server_thread = std::thread(&FGCom_APIServer::serverThreadFunction, this);
        
        // Wait a moment for server to start
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        return server_running;
    } catch (const std::exception& e) {
        std::cerr << "[APIServer] Exception in startServer: " << e.what() << std::endl;
        return false;
    } catch (...) {
        std::cerr << "[APIServer] Unknown exception in startServer" << std::endl;
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
    server->Get("/health", [this](const httplib::Request& req, httplib::Response& res) {
        handleHealthCheckRequest(req, res);
    });
    
    // API information endpoint
    server->Get("/api/info", [this](const httplib::Request& req, httplib::Response& res) {
        nlohmann::json info = {
            {"title", api_config["title"]},
            {"version", api_config["version"]},
            {"description", api_config["description"]},
            {"contact", api_config["contact"]},
            {"features", feature_flags},
            {"endpoints", {
                {"propagation", "/api/v1/propagation"},
                {"solar_data", "/api/v1/solar"},
                {"band_status", "/api/v1/bands"},
                {"antenna_patterns", "/api/v1/antennas"},
                {"ground_systems", "/api/v1/ground"},
                {"gpu_status", "/api/v1/gpu"},
                {"config", "/api/v1/config"},
                {"stats", "/api/v1/stats"}
            }}
        };
        res.set_content(info.dump(), "application/json");
    });
    
    // Propagation endpoints
    if (isFeatureEnabled("propagation")) {
        server->Post("/api/v1/propagation", [this](const httplib::Request& req, httplib::Response& res) {
            handlePropagationRequest(req, res);
        });
        
        server->Post("/api/v1/propagation/batch", [this](const httplib::Request& req, httplib::Response& res) {
            handlePropagationBatchRequest(req, res);
        });
    }
    
    // Solar data endpoints
    if (isFeatureEnabled("solar_data")) {
        server->Get("/api/v1/solar", [this](const httplib::Request& req, httplib::Response& res) {
            handleSolarDataRequest(req, res);
        });
        
        server->Get("/api/v1/solar/history", [this](const httplib::Request& req, httplib::Response& res) {
            handleSolarDataHistoryRequest(req, res);
        });
    }
    
    // Band status endpoints
    if (isFeatureEnabled("band_status")) {
        server->Get("/api/v1/bands", [this](const httplib::Request& req, httplib::Response& res) {
            handleBandStatusAllRequest(req, res);
        });
        
        server->Get("/api/v1/bands/(.*)", [this](const httplib::Request& req, httplib::Response& res) {
            handleBandStatusRequest(req, res);
        });
    }
    
    // Antenna pattern endpoints
    if (isFeatureEnabled("antenna_patterns")) {
        server->Get("/api/v1/antennas", [this](const httplib::Request& req, httplib::Response& res) {
            handleAntennaPatternListRequest(req, res);
        });
        
        server->Get("/api/v1/antennas/(.*)", [this](const httplib::Request& req, httplib::Response& res) {
            handleAntennaPatternRequest(req, res);
        });
    }
    
    // Ground system endpoints
    if (isFeatureEnabled("ground_systems")) {
        server->Get("/api/v1/ground", [this](const httplib::Request& req, httplib::Response& res) {
            handleGroundSystemListRequest(req, res);
        });
        
        server->Get("/api/v1/ground/(.*)", [this](const httplib::Request& req, httplib::Response& res) {
            handleGroundSystemRequest(req, res);
        });
    }
    
    // GPU status endpoints
    if (isFeatureEnabled("gpu_status")) {
        server->Get("/api/v1/gpu", [this](const httplib::Request& req, httplib::Response& res) {
            handleGPUStatusRequest(req, res);
        });
    }
    
    // Configuration endpoints
    server->Get("/api/v1/config", [this](const httplib::Request& req, httplib::Response& res) {
        handleConfigRequest(req, res);
    });
    
    server->Put("/api/v1/config", [this](const httplib::Request& req, httplib::Response& res) {
        handleConfigUpdateRequest(req, res);
    });
    
    server->Get("/api/v1/config/features", [this](const httplib::Request& req, httplib::Response& res) {
        handleFeatureFlagsRequest(req, res);
    });
    
    // Statistics endpoint
    server->Get("/api/v1/stats", [this](const httplib::Request& req, httplib::Response& res) {
        handleStatsRequest(req, res);
    });
    
    // WebSocket endpoint
    if (isFeatureEnabled("websocket")) {
        server->Get("/ws", [this](const httplib::Request& req, httplib::Response& res) {
            handleWebSocketConnection(req, res);
        });
    }
}

void FGCom_APIServer::setupCORS() {
    if (isFeatureEnabled("cors")) {
        server->set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key");
            
            if (req.method == "OPTIONS") {
                res.status = 200;
                return httplib::Server::HandlerResponse::Handled;
            }
            
            return httplib::Server::HandlerResponse::Unhandled;
        });
    }
}

void FGCom_APIServer::setupLogging() {
    server->set_logger([](const httplib::Request& req, const httplib::Response& res) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&time_t);
        
        std::cout << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] "
                  << req.method << " " << req.path << " " << res.status << std::endl;
    });
}

void FGCom_APIServer::setupErrorHandling() {
    server->set_exception_handler([](const httplib::Request& req, httplib::Response& res, std::exception& e) {
        nlohmann::json error = {
            {"error", "Internal Server Error"},
            {"message", e.what()},
            {"path", req.path},
            {"method", req.method}
        };
        res.status = 500;
        res.set_content(error.dump(), "application/json");
    });
}

void FGCom_APIServer::handlePropagationRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        nlohmann::json request_json = nlohmann::json::parse(req.body);
        PropagationRequest prop_req = parsePropagationRequest(request_json);
        
        // Create radio models
        auto radio_model = FGCom_radiowaveModel::selectModel(std::to_string(prop_req.frequency_mhz));
        if (!radio_model) {
            res.status = 400;
            res.set_content(createErrorResponse("Invalid frequency"), "application/json");
            return;
        }
        
        // Calculate propagation
        auto signal = radio_model->getSignal(
            prop_req.lat1, prop_req.lon1, prop_req.alt1,
            prop_req.lat2, prop_req.lon2, prop_req.alt2,
            prop_req.power_watts
        );
        
        // Create response
        PropagationResponse prop_resp;
        prop_resp.success = true;
        prop_resp.signal_quality = signal.quality;
        prop_resp.signal_strength_db = 20.0 * log10(signal.quality + 0.001);
        prop_resp.distance_km = signal.distance;
        prop_resp.bearing_deg = signal.direction;
        prop_resp.elevation_angle_deg = signal.verticalAngle;
        prop_resp.propagation_mode = "skywave"; // Simplified
        
        // Add solar effects if enabled
        if (prop_req.include_solar_effects) {
            FGCom_SolarDataProvider solar_provider;
            auto solar = solar_provider.getCurrentConditions();
            prop_resp.solar_effect_db = 10.0 * log10(solar.sfi / 70.0); // Simplified solar effect
        }
        
        res.set_content(createSuccessResponse(propagationResponseToJSON(prop_resp)), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 400;
        res.set_content(createErrorResponse("Invalid request: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleSolarDataRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        FGCom_SolarDataProvider solar_provider;
        auto solar = solar_provider.getCurrentConditions();
        
        res.set_content(createSuccessResponse(solarConditionsToJSON(solar)), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get solar data: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleBandStatusRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        std::string band = req.matches[1];
        std::string mode = req.get_param_value("mode");
        
        BandStatusResponse band_resp;
        band_resp.band = band;
        band_resp.mode = mode.empty() ? "SSB" : mode;
        band_resp.frequency_mhz = 14.0; // Simplified
        band_resp.is_open = true; // Simplified
        band_resp.signal_quality = 0.8; // Simplified
        band_resp.propagation_conditions = "Good";
        band_resp.solar_conditions = "Quiet";
        
        res.set_content(createSuccessResponse(bandStatusResponseToJSON(band_resp)), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 400;
        res.set_content(createErrorResponse("Invalid request: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleBandStatusAllRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        std::vector<std::string> bands = {"160m", "80m", "40m", "20m", "15m", "10m"};
        nlohmann::json bands_json = nlohmann::json::array();
        
        for (const auto& band : bands) {
            BandStatusResponse band_resp;
            band_resp.band = band;
            band_resp.mode = "SSB";
            band_resp.frequency_mhz = 14.0; // Simplified
            band_resp.is_open = true; // Simplified
            band_resp.signal_quality = 0.8; // Simplified
            band_resp.propagation_conditions = "Good";
            band_resp.solar_conditions = "Quiet";
            
            bands_json.push_back(bandStatusResponseToJSON(band_resp));
        }
        
        res.set_content(createSuccessResponse(bands_json), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get band status: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleAntennaPatternRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        std::string antenna_name = req.matches[1];
        float frequency_mhz = std::stof(req.get_param_value("frequency", "14.0"));
        
        AntennaPatternResponse pattern_resp;
        pattern_resp.antenna_name = antenna_name;
        pattern_resp.frequency_mhz = frequency_mhz;
        pattern_resp.polarization = "vertical";
        pattern_resp.is_loaded = false; // Simplified - would load actual pattern
        
        res.set_content(createSuccessResponse(antennaPatternResponseToJSON(pattern_resp)), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 400;
        res.set_content(createErrorResponse("Invalid request: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleAntennaPatternListRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        std::vector<std::string> patterns = {"vertical_1_4", "dipole_1_2", "yagi_3el", "yagi_5el"};
        nlohmann::json patterns_json = nlohmann::json::array();
        
        for (const auto& pattern : patterns) {
            patterns_json.push_back({
                {"name", pattern},
                {"type", "4NEC2"},
                {"frequency_range", "1.8-30.0"},
                {"available", true}
            });
        }
        
        res.set_content(createSuccessResponse(patterns_json), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get antenna patterns: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleGroundSystemRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        std::string system_name = req.matches[1];
        
        FGCom_AntennaGroundSystem::initialize();
        auto ground_system = FGCom_AntennaGroundSystem::getPredefinedGroundSystem(system_name);
        
        nlohmann::json ground_json = {
            {"name", system_name},
            {"type", ground_system.type},
            {"conductivity", ground_system.conductivity},
            {"area_coverage", ground_system.area_coverage},
            {"ground_resistance", ground_system.ground_resistance},
            {"is_saltwater", ground_system.is_saltwater},
            {"material", ground_system.material},
            {"notes", ground_system.notes}
        };
        
        res.set_content(createSuccessResponse(ground_json), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 400;
        res.set_content(createErrorResponse("Invalid request: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleGroundSystemListRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        FGCom_AntennaGroundSystem::initialize();
        auto systems = FGCom_AntennaGroundSystem::getAvailableGroundSystems();
        
        nlohmann::json systems_json = nlohmann::json::array();
        for (const auto& system : systems) {
            systems_json.push_back({
                {"name", system},
                {"available", true}
            });
        }
        
        res.set_content(createSuccessResponse(systems_json), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get ground systems: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleGPUStatusRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        GPUStatusResponse gpu_resp;
        gpu_resp.gpu_available = false; // Simplified - would detect actual GPU
        gpu_resp.gpu_name = "None";
        gpu_resp.gpu_memory_mb = 0;
        gpu_resp.gpu_utilization = 0.0;
        gpu_resp.cuda_available = false;
        gpu_resp.opencl_available = false;
        
        res.set_content(createSuccessResponse(gpuStatusResponseToJSON(gpu_resp)), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get GPU status: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleConfigRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        auto& config = FGCom_Config::getInstance();
        res.set_content(createSuccessResponse(config.toJSON()), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get configuration: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleConfigUpdateRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        nlohmann::json config_json = nlohmann::json::parse(req.body);
        auto& config = FGCom_Config::getInstance();
        
        if (config.fromJSON(config_json)) {
            config.saveConfig();
            res.set_content(createSuccessResponse({{"message", "Configuration updated successfully"}}), "application/json");
        } else {
            res.status = 400;
            res.set_content(createErrorResponse("Invalid configuration"), "application/json");
        }
        
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 400;
        res.set_content(createErrorResponse("Invalid request: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleFeatureFlagsRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        res.set_content(createSuccessResponse(nlohmann::json(feature_flags)), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get feature flags: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleStatsRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        auto now = std::chrono::system_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - server_start_time).count();
        
        nlohmann::json stats = {
            {"server", {
                {"uptime_seconds", uptime},
                {"total_requests", total_requests.load()},
                {"total_websocket_connections", total_websocket_connections.load()},
                {"active_websocket_connections", websocket_clients.size()},
                {"rate_limit_requests_per_minute", rate_limit_requests_per_minute}
            }},
            {"features", feature_flags},
            {"version", api_config["version"]}
        };
        
        res.set_content(createSuccessResponse(stats), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get statistics: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleHealthCheckRequest(const httplib::Request& req, httplib::Response& res) {
    nlohmann::json health = {
        {"status", "healthy"},
        {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()},
        {"version", api_config["version"]},
        {"features", feature_flags}
    };
    
    res.set_content(health.dump(), "application/json");
}

void FGCom_APIServer::handleWebSocketConnection(const httplib::Request& req, httplib::Response& res) {
    if (!websocket_enabled) {
        res.status = 503;
        res.set_content("WebSocket not enabled", "text/plain");
        return;
    }
    
    // Simplified WebSocket handling - would need proper WebSocket implementation
    std::lock_guard<std::mutex> lock(websocket_mutex);
    auto client = std::make_unique<WebSocketClient>(next_client_id++, "/ws");
    websocket_clients.push_back(std::move(client));
    total_websocket_connections++;
    
    res.status = 101; // Switching Protocols
    res.set_header("Upgrade", "websocket");
    res.set_header("Connection", "Upgrade");
}

void FGCom_APIServer::serverThreadFunction() {
    server_running = true;
    
    if (!server->listen(server_host, server_port)) {
        server_running = false;
        std::cerr << "Failed to start API server on " << server_host << ":" << server_port << std::endl;
        return;
    }
    
    std::cout << "API server started on " << server_host << ":" << server_port << std::endl;
}

bool FGCom_APIServer::checkRateLimit(const std::string& client_ip) {
    if (!isFeatureEnabled("rate_limiting")) {
        return true;
    }
    
    std::lock_guard<std::mutex> lock(rate_limit_mutex);
    auto now = std::chrono::system_clock::now();
    auto minute_ago = now - std::chrono::minutes(1);
    
    // Clean old entries
    for (auto it = rate_limit_map.begin(); it != rate_limit_map.end();) {
        if (it->second < minute_ago) {
            it = rate_limit_map.erase(it);
        } else {
            ++it;
        }
    }
    
    // Check current rate
    int request_count = 0;
    for (const auto& entry : rate_limit_map) {
        if (entry.first == client_ip && entry.second > minute_ago) {
            request_count++;
        }
    }
    
    if (request_count >= rate_limit_requests_per_minute) {
        return false;
    }
    
    rate_limit_map[client_ip] = now;
    return true;
}

void FGCom_APIServer::setFeatureFlag(const std::string& feature, bool enabled) {
    std::lock_guard<std::mutex> lock(config_mutex);
    feature_flags[feature] = enabled;
}

bool FGCom_APIServer::isFeatureEnabled(const std::string& feature) const {
    std::lock_guard<std::mutex> lock(config_mutex);
    auto it = feature_flags.find(feature);
    return it != feature_flags.end() ? it->second : false;
}

void FGCom_APIServer::setAPIConfig(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(config_mutex);
    api_config[key] = value;
}

std::string FGCom_APIServer::getAPIConfig(const std::string& key, const std::string& default_value) const {
    std::lock_guard<std::mutex> lock(config_mutex);
    auto it = api_config.find(key);
    return it != api_config.end() ? it->second : default_value;
}

void FGCom_APIServer::setRateLimit(int requests_per_minute) {
    rate_limit_requests_per_minute = requests_per_minute;
}

void FGCom_APIServer::enableWebSocket(bool enabled) {
    websocket_enabled = enabled;
}

void FGCom_APIServer::broadcastToWebSocketClients(const std::string& message) {
    std::lock_guard<std::mutex> lock(websocket_mutex);
    for (auto& client : websocket_clients) {
        if (client->is_active) {
            // Simplified - would send actual WebSocket message
            client->last_activity = std::chrono::system_clock::now();
        }
    }
}

void FGCom_APIServer::broadcastToWebSocketClients(const std::string& endpoint, const std::string& message) {
    std::lock_guard<std::mutex> lock(websocket_mutex);
    for (auto& client : websocket_clients) {
        if (client->is_active && client->endpoint == endpoint) {
            // Simplified - would send actual WebSocket message
            client->last_activity = std::chrono::system_clock::now();
        }
    }
}

void FGCom_APIServer::removeInactiveWebSocketClients() {
    std::lock_guard<std::mutex> lock(websocket_mutex);
    auto now = std::chrono::system_clock::now();
    auto timeout = std::chrono::minutes(5);
    
    websocket_clients.erase(
        std::remove_if(websocket_clients.begin(), websocket_clients.end(),
            [&](const std::unique_ptr<WebSocketClient>& client) {
                return !client->is_active || (now - client->last_activity) > timeout;
            }),
        websocket_clients.end()
    );
}

std::string FGCom_APIServer::getClientIP(const httplib::Request& req) const {
    // Try to get real IP from headers
    auto x_forwarded_for = req.get_header_value("X-Forwarded-For");
    if (!x_forwarded_for.empty()) {
        return x_forwarded_for.substr(0, x_forwarded_for.find(','));
    }
    
    auto x_real_ip = req.get_header_value("X-Real-IP");
    if (!x_real_ip.empty()) {
        return x_real_ip;
    }
    
    return req.remote_addr;
}

std::string FGCom_APIServer::createErrorResponse(const std::string& error_message, int error_code) const {
    nlohmann::json error = {
        {"error", true},
        {"message", error_message},
        {"code", error_code},
        {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()}
    };
    return error.dump();
}

std::string FGCom_APIServer::createSuccessResponse(const nlohmann::json& data) const {
    nlohmann::json response = {
        {"success", true},
        {"data", data},
        {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()}
    };
    return response.dump();
}

// JSON conversion functions
nlohmann::json FGCom_APIServer::propagationRequestToJSON(const PropagationRequest& req) const {
    return {
        {"lat1", req.lat1},
        {"lon1", req.lon1},
        {"lat2", req.lat2},
        {"lon2", req.lon2},
        {"alt1", req.alt1},
        {"alt2", req.alt2},
        {"frequency_mhz", req.frequency_mhz},
        {"power_watts", req.power_watts},
        {"antenna_type", req.antenna_type},
        {"ground_type", req.ground_type},
        {"mode", req.mode},
        {"band", req.band},
        {"include_solar_effects", req.include_solar_effects},
        {"include_antenna_patterns", req.include_antenna_patterns}
    };
}

nlohmann::json FGCom_APIServer::propagationResponseToJSON(const PropagationResponse& resp) const {
    return {
        {"signal_quality", resp.signal_quality},
        {"signal_strength_db", resp.signal_strength_db},
        {"path_loss_db", resp.path_loss_db},
        {"antenna_gain_db", resp.antenna_gain_db},
        {"ground_loss_db", resp.ground_loss_db},
        {"solar_effect_db", resp.solar_effect_db},
        {"distance_km", resp.distance_km},
        {"bearing_deg", resp.bearing_deg},
        {"elevation_angle_deg", resp.elevation_angle_deg},
        {"propagation_mode", resp.propagation_mode},
        {"success", resp.success},
        {"error_message", resp.error_message}
    };
}

nlohmann::json FGCom_APIServer::bandStatusResponseToJSON(const BandStatusResponse& resp) const {
    return {
        {"band", resp.band},
        {"mode", resp.mode},
        {"frequency_mhz", resp.frequency_mhz},
        {"is_open", resp.is_open},
        {"muf_mhz", resp.muf_mhz},
        {"luf_mhz", resp.luf_mhz},
        {"signal_quality", resp.signal_quality},
        {"propagation_conditions", resp.propagation_conditions},
        {"solar_conditions", resp.solar_conditions},
        {"active_stations", resp.active_stations},
        {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
            resp.timestamp.time_since_epoch()).count()}
    };
}

nlohmann::json FGCom_APIServer::antennaPatternResponseToJSON(const AntennaPatternResponse& resp) const {
    return {
        {"antenna_name", resp.antenna_name},
        {"frequency_mhz", resp.frequency_mhz},
        {"polarization", resp.polarization},
        {"azimuth_angles", resp.azimuth_angles},
        {"elevation_angles", resp.elevation_angles},
        {"gain_values", resp.gain_values},
        {"phase_values", resp.phase_values},
        {"is_loaded", resp.is_loaded},
        {"error_message", resp.error_message}
    };
}

nlohmann::json FGCom_APIServer::gpuStatusResponseToJSON(const GPUStatusResponse& resp) const {
    return {
        {"gpu_available", resp.gpu_available},
        {"gpu_name", resp.gpu_name},
        {"gpu_memory_mb", resp.gpu_memory_mb},
        {"gpu_utilization", resp.gpu_utilization},
        {"cuda_available", resp.cuda_available},
        {"opencl_available", resp.opencl_available},
        {"error_message", resp.error_message}
    };
}

nlohmann::json FGCom_APIServer::solarConditionsToJSON(const fgcom_solar_conditions& solar) const {
    return {
        {"sfi", solar.sfi},
        {"k_index", solar.k_index},
        {"a_index", solar.a_index},
        {"solar_zenith", solar.solar_zenith},
        {"is_day", solar.is_day},
        {"day_of_year", solar.day_of_year},
        {"solar_declination", solar.solar_declination},
        {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
            solar.timestamp.time_since_epoch()).count()}
    };
}

PropagationRequest FGCom_APIServer::parsePropagationRequest(const nlohmann::json& json) const {
    PropagationRequest req;
    
    req.lat1 = json.value("lat1", 0.0);
    req.lon1 = json.value("lon1", 0.0);
    req.lat2 = json.value("lat2", 0.0);
    req.lon2 = json.value("lon2", 0.0);
    req.alt1 = json.value("alt1", 0.0f);
    req.alt2 = json.value("alt2", 0.0f);
    req.frequency_mhz = json.value("frequency_mhz", 14.0f);
    req.power_watts = json.value("power_watts", 100.0f);
    req.antenna_type = json.value("antenna_type", "vertical");
    req.ground_type = json.value("ground_type", "average");
    req.mode = json.value("mode", "SSB");
    req.band = json.value("band", "20m");
    req.include_solar_effects = json.value("include_solar_effects", true);
    req.include_antenna_patterns = json.value("include_antenna_patterns", true);
    
    return req;
}

void FGCom_APIServer::broadcastPropagationUpdate(const fgcom_solar_conditions& solar) {
    nlohmann::json update = {
        {"type", "solar_update"},
        {"data", solarConditionsToJSON(solar)}
    };
    broadcastToWebSocketClients("/ws", update.dump());
}

void FGCom_APIServer::broadcastBandStatusUpdate(const std::string& band, const BandStatusResponse& status) {
    nlohmann::json update = {
        {"type", "band_status_update"},
        {"band", band},
        {"data", bandStatusResponseToJSON(status)}
    };
    broadcastToWebSocketClients("/ws", update.dump());
}

void FGCom_APIServer::broadcastAntennaPatternUpdate(const std::string& antenna_name, const AntennaPatternResponse& pattern) {
    nlohmann::json update = {
        {"type", "antenna_pattern_update"},
        {"antenna_name", antenna_name},
        {"data", antennaPatternResponseToJSON(pattern)}
    };
    broadcastToWebSocketClients("/ws", update.dump());
}

long FGCom_APIServer::getTotalRequests() const {
    return total_requests.load();
}

long FGCom_APIServer::getTotalWebSocketConnections() const {
    return total_websocket_connections.load();
}

std::chrono::system_clock::time_point FGCom_APIServer::getServerStartTime() const {
    return server_start_time;
}

std::map<std::string, std::string> FGCom_APIServer::getServerStats() const {
    auto now = std::chrono::system_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - server_start_time).count();
    
    return {
        {"uptime_seconds", std::to_string(uptime)},
        {"total_requests", std::to_string(total_requests.load())},
        {"total_websocket_connections", std::to_string(total_websocket_connections.load())},
        {"active_websocket_connections", std::to_string(websocket_clients.size())},
        {"rate_limit_requests_per_minute", std::to_string(rate_limit_requests_per_minute)},
        {"version", api_config.at("version")}
    };
}
