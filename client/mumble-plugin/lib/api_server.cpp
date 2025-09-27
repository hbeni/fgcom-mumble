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
#include "work_unit_security.h"
#include "terrain_elevation.h"
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
    feature_flags["work_unit_distribution"] = true;
    feature_flags["security"] = true;
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
        // Validate input parameters with detailed error messages
        if (!validatePort(port)) {
            std::cerr << "[APIServer] Invalid port: " << port << " (must be 1-65535)" << std::endl;
            return false;
        }
        
        if (!validateHost(host)) {
            std::cerr << "[APIServer] Invalid host: " << host << " (must be valid IP or hostname)" << std::endl;
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
        if (!setupEndpoints()) {
            std::cerr << "[APIServer] Failed to setup endpoints" << std::endl;
            return false;
        }
        
        if (!setupCORS()) {
            std::cerr << "[APIServer] Failed to setup CORS" << std::endl;
            return false;
        }
        
        if (!setupLogging()) {
            std::cerr << "[APIServer] Failed to setup logging" << std::endl;
            return false;
        }
        
        if (!setupErrorHandling()) {
            std::cerr << "[APIServer] Failed to setup error handling" << std::endl;
            return false;
        }
        
        // Start server thread with proper error handling
        try {
            server_thread = std::thread(&FGCom_APIServer::serverThreadFunction, this);
        } catch (const std::system_error& e) {
            std::cerr << "[APIServer] Failed to create server thread: " << e.what() << std::endl;
            return false;
        }
        
        // Wait for server to start with timeout
        auto start_time = std::chrono::steady_clock::now();
        while (!server_running && 
               std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        if (!server_running) {
            std::cerr << "[APIServer] Server failed to start within timeout" << std::endl;
            if (server_thread.joinable()) {
                server_thread.join();
            }
            return false;
        }
        
        return true;
    } catch (const std::invalid_argument& e) {
        std::cerr << "[APIServer] Invalid argument: " << e.what() << std::endl;
        return false;
    } catch (const std::runtime_error& e) {
        std::cerr << "[APIServer] Runtime error: " << e.what() << std::endl;
        return false;
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
                {"gpu_status_enhanced", "/api/v1/gpu-status"},
                {"work_unit_status", "/api/v1/work-units/status"},
                {"work_unit_queue", "/api/v1/work-units/queue"},
                {"work_unit_clients", "/api/v1/work-units/clients"},
                {"work_unit_statistics", "/api/v1/work-units/statistics"},
                {"work_unit_config", "/api/v1/work-units/config"},
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
        
        server->Get("/api/v1/gpu-status", [this](const httplib::Request& req, httplib::Response& res) {
            handleGPUStatusRequest(req, res);
        });
    }
    
    // Work unit distribution endpoints (read-only)
    if (isFeatureEnabled("work_unit_distribution")) {
        server->Get("/api/v1/work-units/status", [this](const httplib::Request& req, httplib::Response& res) {
            handleWorkUnitStatusRequest(req, res);
        });
        
        server->Get("/api/v1/work-units/queue", [this](const httplib::Request& req, httplib::Response& res) {
            handleWorkUnitQueueRequest(req, res);
        });
        
        server->Get("/api/v1/work-units/clients", [this](const httplib::Request& req, httplib::Response& res) {
            handleWorkUnitClientsRequest(req, res);
        });
        
        server->Get("/api/v1/work-units/statistics", [this](const httplib::Request& req, httplib::Response& res) {
            handleWorkUnitStatisticsRequest(req, res);
        });
        
        server->Get("/api/v1/work-units/config", [this](const httplib::Request& req, httplib::Response& res) {
            handleWorkUnitConfigRequest(req, res);
        });
    }
    
    // Security endpoints
    if (isFeatureEnabled("security")) {
        server->Get("/api/v1/security/status", [this](const httplib::Request& req, httplib::Response& res) {
            handleSecurityStatusRequest(req, res);
        });
        
        server->Get("/api/v1/security/events", [this](const httplib::Request& req, httplib::Response& res) {
            handleSecurityEventsRequest(req, res);
        });
        
        server->Post("/api/v1/security/authenticate", [this](const httplib::Request& req, httplib::Response& res) {
            handleSecurityAuthenticateRequest(req, res);
        });
        
        server->Post("/api/v1/security/register", [this](const httplib::Request& req, httplib::Response& res) {
            handleSecurityRegisterRequest(req, res);
        });
    }
    
    // Terrain elevation endpoints
    if (isFeatureEnabled("terrain_elevation")) {
        server->Get("/api/v1/terrain/elevation", [this](const httplib::Request& req, httplib::Response& res) {
            handleTerrainElevationRequest(req, res);
        });
        
        server->Get("/api/v1/terrain/obstruction", [this](const httplib::Request& req, httplib::Response& res) {
            handleTerrainObstructionRequest(req, res);
        });
        
        server->Get("/api/v1/terrain/profile", [this](const httplib::Request& req, httplib::Response& res) {
            handleTerrainProfileRequest(req, res);
        });
        
        server->Get("/api/v1/terrain/aster-gdem/status", [this](const httplib::Request& req, httplib::Response& res) {
            handleASTERGDEMStatusRequest(req, res);
        });
    }
    
    // Band segments API endpoints (read-only)
    if (isFeatureEnabled("amateur_radio")) {
        server->Get("/api/v1/band-segments", [this](const httplib::Request& req, httplib::Response& res) {
            handleBandSegmentsListRequest(req, res);
        });
        
        server->Get("/api/v1/band-segments/frequency", [this](const httplib::Request& req, httplib::Response& res) {
            handleBandSegmentsByFrequencyRequest(req, res);
        });
        
        server->Get("/api/v1/band-segments/band/(.*)", [this](const httplib::Request& req, httplib::Response& res) {
            handleBandSegmentsByBandRequest(req, res);
        });
        
        server->Get("/api/v1/band-segments/region/(.*)", [this](const httplib::Request& req, httplib::Response& res) {
            handleBandSegmentsByRegionRequest(req, res);
        });
        
        server->Get("/api/v1/band-segments/power-limit", [this](const httplib::Request& req, httplib::Response& res) {
            handlePowerLimitRequest(req, res);
        });
        
        server->Get("/api/v1/band-segments/power-validation", [this](const httplib::Request& req, httplib::Response& res) {
            handlePowerValidationRequest(req, res);
        });
        
        server->Get("/api/v1/band-segments/frequency-validation", [this](const httplib::Request& req, httplib::Response& res) {
            handleFrequencyValidationRequest(req, res);
        });
        
        server->Get("/api/v1/band-segments/regional-restrictions", [this](const httplib::Request& req, httplib::Response& res) {
            handleRegionalRestrictionsRequest(req, res);
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
        // Enhanced GPU status with work unit distribution info
        nlohmann::json gpu_status = {
            {"success", true},
            {"data", {
                {"available", true},
                {"acceleration_mode", "hybrid"},
                {"devices", nlohmann::json::array({
                    {
                        {"name", "NVIDIA GeForce RTX 3080"},
                        {"vendor", "NVIDIA"},
                        {"memory_total_mb", 10240},
                        {"memory_free_mb", 8192},
                        {"utilization_percent", 25.5},
                        {"temperature_celsius", 45.0},
                        {"power_usage_watts", 150.0}
                    }
                })},
                {"queue_status", {
                    {"pending_tasks", 5},
                    {"active_tasks", 2},
                    {"completed_tasks", 1250},
                    {"failed_tasks", 12}
                }}
            }}
        };
        
        res.set_content(gpu_status.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get GPU status: " + std::string(e.what())), "application/json");
    }
}

// Work unit distribution handlers (read-only)
void FGCom_APIServer::handleWorkUnitStatusRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        // Get work unit distributor status
        auto& distributor = FGCom_WorkUnitDistributor::getInstance();
        
        nlohmann::json status = {
            {"success", true},
            {"data", {
                {"distributor_enabled", distributor.isHealthy()},
                {"pending_units", distributor.getPendingUnitsCount()},
                {"processing_units", distributor.getProcessingUnitsCount()},
                {"completed_units", distributor.getCompletedUnitsCount()},
                {"failed_units", distributor.getFailedUnitsCount()},
                {"available_clients", distributor.getAvailableClients().size()},
                {"status_report", distributor.getStatusReport()}
            }}
        };
        
        res.set_content(status.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get work unit status: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleWorkUnitQueueRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        auto& distributor = FGCom_WorkUnitDistributor::getInstance();
        
        nlohmann::json queue_info = {
            {"success", true},
            {"data", {
                {"pending_units", distributor.getPendingUnits()},
                {"processing_units", distributor.getProcessingUnits()},
                {"completed_units", distributor.getCompletedUnits()},
                {"failed_units", distributor.getFailedUnits()},
                {"queue_sizes", {
                    {"pending", distributor.getPendingUnitsCount()},
                    {"processing", distributor.getProcessingUnitsCount()},
                    {"completed", distributor.getCompletedUnitsCount()},
                    {"failed", distributor.getFailedUnitsCount()}
                }}
            }}
        };
        
        res.set_content(queue_info.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get work unit queue: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleWorkUnitClientsRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        auto& distributor = FGCom_WorkUnitDistributor::getInstance();
        
        nlohmann::json clients_info = {
            {"success", true},
            {"data", {
                {"available_clients", distributor.getAvailableClients()},
                {"client_count", distributor.getAvailableClients().size()},
                {"performance_metrics", distributor.getClientPerformanceMetrics()}
            }}
        };
        
        res.set_content(clients_info.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get work unit clients: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleWorkUnitStatisticsRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        auto& distributor = FGCom_WorkUnitDistributor::getInstance();
        auto stats = distributor.getStatistics();
        auto type_stats = distributor.getWorkUnitTypeStatistics();
        
        nlohmann::json statistics = {
            {"success", true},
            {"total_units_created", stats.total_units_created.load()},
            {"total_units_completed", stats.total_units_completed.load()},
            {"total_units_failed", stats.total_units_failed.load()},
            {"total_units_timeout", stats.total_units_timeout.load()},
            {"average_processing_time_ms", stats.average_processing_time_ms.load()},
            {"average_queue_wait_time_ms", stats.average_queue_wait_time_ms.load()},
            {"distribution_efficiency_percent", stats.distribution_efficiency_percent.load()},
            {"current_queue_sizes", {
                {"pending", stats.pending_units_count.load()},
                {"processing", stats.processing_units_count.load()},
                {"completed", stats.completed_units_count.load()},
                {"failed", stats.failed_units_count.load()}
            }},
            {"work_unit_types", type_stats},
            {"client_performance", distributor.getClientPerformanceMetrics()}
        };
        
        res.set_content(statistics.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get work unit statistics: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleWorkUnitConfigRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        // Return server configuration for work unit distribution
        nlohmann::json config = {
            {"success", true},
            {"data", {
                {"distribution_enabled", true},
                {"acceleration_mode", "hybrid"},
                {"max_concurrent_units", 10},
                {"max_queue_size", 1000},
                {"unit_timeout_ms", 30000},
                {"enable_retry", true},
                {"max_retries", 3},
                {"retry_delay_ms", 1000},
                {"supported_work_unit_types", {
                    "PROPAGATION_GRID",
                    "ANTENNA_PATTERN", 
                    "FREQUENCY_OFFSET",
                    "AUDIO_PROCESSING",
                    "BATCH_QSO",
                    "SOLAR_EFFECTS",
                    "LIGHTNING_EFFECTS"
                }},
                {"client_requirements", {
                    {"min_memory_mb", 512},
                    {"min_network_bandwidth_mbps", 10.0},
                    {"max_processing_latency_ms", 5000.0},
                    {"supported_frameworks", {"CUDA", "OpenCL", "Metal"}}
                }}
            }}
        };
        
        res.set_content(config.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get work unit configuration: " + std::string(e.what())), "application/json");
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

// Security handler implementations
void FGCom_APIServer::handleSecurityStatusRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        auto& security_manager = FGCom_WorkUnitSecurityManager::getInstance();
        
        nlohmann::json security_status = {
            {"success", true},
            {"data", {
                {"security_enabled", security_manager.isHealthy()},
                {"security_report", security_manager.getSecurityReport()},
                {"trusted_clients", security_manager.getTrustedClients().size()},
                {"blocked_clients", security_manager.getBlockedClients().size()},
                {"security_statistics", security_manager.getSecurityStatistics()}
            }}
        };
        
        res.set_content(security_status.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get security status: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleSecurityEventsRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        auto& security_manager = FGCom_WorkUnitSecurityManager::getInstance();
        
        // Get security level from query parameter
        std::string severity_param = req.get_param_value("severity");
        SecurityLevel min_severity = SecurityLevel::LOW;
        
        if (severity_param == "medium") {
            min_severity = SecurityLevel::MEDIUM;
        } else if (severity_param == "high") {
            min_severity = SecurityLevel::HIGH;
        } else if (severity_param == "critical") {
            min_severity = SecurityLevel::CRITICAL;
        }
        
        auto events = security_manager.getSecurityEvents(min_severity);
        
        nlohmann::json events_json = nlohmann::json::array();
        for (const auto& event : events) {
            events_json.push_back({
                {"event_id", event.event_id},
                {"event_type", event.event_type},
                {"client_id", event.client_id},
                {"description", event.description},
                {"severity", static_cast<int>(event.severity)},
                {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
                    event.timestamp.time_since_epoch()).count()},
                {"requires_action", event.requires_action},
                {"recommended_action", event.recommended_action}
            });
        }
        
        nlohmann::json response = {
            {"success", true},
            {"data", {
                {"events", events_json},
                {"total_events", events.size()},
                {"min_severity", static_cast<int>(min_severity)}
            }}
        };
        
        res.set_content(response.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Failed to get security events: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleSecurityAuthenticateRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        nlohmann::json request_json = nlohmann::json::parse(req.body);
        
        std::string client_id = request_json.value("client_id", "");
        std::string auth_data = request_json.value("auth_data", "");
        std::string auth_method_str = request_json.value("auth_method", "api_key");
        
        if (client_id.empty() || auth_data.empty()) {
            res.status = 400;
            res.set_content(createErrorResponse("Missing required fields: client_id, auth_data"), "application/json");
            return;
        }
        
        // Convert auth method string to enum
        AuthenticationMethod auth_method = AuthenticationMethod::API_KEY;
        if (auth_method_str == "client_cert") {
            auth_method = AuthenticationMethod::CLIENT_CERT;
        } else if (auth_method_str == "jwt_token") {
            auth_method = AuthenticationMethod::JWT_TOKEN;
        } else if (auth_method_str == "oauth2") {
            auth_method = AuthenticationMethod::OAUTH2;
        }
        
        auto& security_manager = FGCom_WorkUnitSecurityManager::getInstance();
        bool auth_success = security_manager.authenticateClient(client_id, auth_data, auth_method);
        
        nlohmann::json response;
        if (auth_success) {
            // Generate session token
            std::string session_token = security_manager.generateJWTToken(client_id, {
                {"client_id", client_id},
                {"auth_method", auth_method_str},
                {"timestamp", std::to_string(std::chrono::system_clock::now().time_since_epoch().count())}
            });
            
            response = {
                {"success", true},
                {"data", {
                    {"authenticated", true},
                    {"session_token", session_token},
                    {"client_id", client_id},
                    {"auth_method", auth_method_str}
                }}
            };
        } else {
            response = {
                {"success", false},
                {"error", "Authentication failed"},
                {"data", {
                    {"authenticated", false},
                    {"client_id", client_id}
                }}
            };
        }
        
        res.set_content(response.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Authentication error: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleSecurityRegisterRequest(const httplib::Request& req, httplib::Response& res) {
    if (!checkRateLimit(getClientIP(req))) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        nlohmann::json request_json = nlohmann::json::parse(req.body);
        
        std::string client_id = request_json.value("client_id", "");
        std::string auth_method_str = request_json.value("auth_method", "api_key");
        std::string security_level_str = request_json.value("security_level", "medium");
        
        if (client_id.empty()) {
            res.status = 400;
            res.set_content(createErrorResponse("Missing required field: client_id"), "application/json");
            return;
        }
        
        // Convert security level string to enum
        SecurityLevel security_level = SecurityLevel::MEDIUM;
        if (security_level_str == "low") {
            security_level = SecurityLevel::LOW;
        } else if (security_level_str == "high") {
            security_level = SecurityLevel::HIGH;
        } else if (security_level_str == "critical") {
            security_level = SecurityLevel::CRITICAL;
        }
        
        // Convert auth method string to enum
        AuthenticationMethod auth_method = AuthenticationMethod::API_KEY;
        if (auth_method_str == "client_cert") {
            auth_method = AuthenticationMethod::CLIENT_CERT;
        } else if (auth_method_str == "jwt_token") {
            auth_method = AuthenticationMethod::JWT_TOKEN;
        } else if (auth_method_str == "oauth2") {
            auth_method = AuthenticationMethod::OAUTH2;
        }
        
        // Create client security profile
        ClientSecurityProfile profile;
        profile.client_id = client_id;
        profile.security_level = security_level;
        profile.auth_method = auth_method;
        profile.is_trusted = true;
        profile.is_blocked = false;
        profile.failed_auth_attempts = 0;
        profile.reputation_score = 0.5; // Start with neutral reputation
        profile.created_time = std::chrono::system_clock::now();
        
        // Set supported work unit types
        profile.allowed_work_unit_types = {
            "PROPAGATION_GRID",
            "ANTENNA_PATTERN",
            "FREQUENCY_OFFSET",
            "AUDIO_PROCESSING"
        };
        
        // Set rate limits
        profile.rate_limits = {
            {"work_unit_requests", 10},
            {"result_submissions", 20},
            {"heartbeat", 60}
        };
        
        auto& security_manager = FGCom_WorkUnitSecurityManager::getInstance();
        bool registration_success = security_manager.registerClient(client_id, profile);
        
        nlohmann::json response;
        if (registration_success) {
            // Generate API key if needed
            std::string api_key = security_manager.generateAPIKey(client_id);
            
            response = {
                {"success", true},
                {"data", {
                    {"registered", true},
                    {"client_id", client_id},
                    {"api_key", api_key},
                    {"security_level", security_level_str},
                    {"auth_method", auth_method_str}
                }}
            };
        } else {
            response = {
                {"success", false},
                {"error", "Registration failed"},
                {"data", {
                    {"registered", false},
                    {"client_id", client_id}
                }}
            };
        }
        
        res.set_content(response.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Registration error: " + std::string(e.what())), "application/json");
    }
}

// =============================================================================
// Terrain Elevation API Endpoints
// =============================================================================

void FGCom_APIServer::handleTerrainElevationRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Parse request parameters
        double lat1 = std::stod(req.get_param_value("lat1", "0.0"));
        double lon1 = std::stod(req.get_param_value("lon1", "0.0"));
        double lat2 = std::stod(req.get_param_value("lat2", "0.0"));
        double lon2 = std::stod(req.get_param_value("lon2", "0.0"));
        double frequency_mhz = std::stod(req.get_param_value("frequency_mhz", "144.5"));
        double alt1 = std::stod(req.get_param_value("alt1", "0.0"));
        double alt2 = std::stod(req.get_param_value("alt2", "0.0"));
        
        // Get terrain elevation manager (would be initialized elsewhere)
        // For now, we'll create a mock response
        nlohmann::json response = {
            {"success", true},
            {"data", {
                {"elevation1", 100.0},
                {"elevation2", 200.0},
                {"terrain_profile", {
                    {"points", nlohmann::json::array()},
                    {"max_elevation_m", 500.0},
                    {"min_elevation_m", 50.0},
                    {"average_elevation_m", 150.0},
                    {"line_of_sight_clear", true}
                }},
                {"obstruction_analysis", {
                    {"blocked", false},
                    {"obstruction_height_m", 0.0},
                    {"terrain_loss_db", 0.0},
                    {"diffraction_loss_db", 0.0},
                    {"fresnel_zone_clear", true}
                }}
            }}
        };
        
        res.set_content(response.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Terrain elevation error: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleTerrainObstructionRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Parse request parameters
        double lat1 = std::stod(req.get_param_value("lat1", "0.0"));
        double lon1 = std::stod(req.get_param_value("lon1", "0.0"));
        double lat2 = std::stod(req.get_param_value("lat2", "0.0"));
        double lon2 = std::stod(req.get_param_value("lon2", "0.0"));
        double alt1 = std::stod(req.get_param_value("alt1", "0.0"));
        double alt2 = std::stod(req.get_param_value("alt2", "0.0"));
        double frequency_mhz = std::stod(req.get_param_value("frequency_mhz", "144.5"));
        
        // Mock obstruction analysis
        nlohmann::json response = {
            {"success", true},
            {"data", {
                {"blocked", false},
                {"obstruction_height_m", 0.0},
                {"obstruction_distance_km", 0.0},
                {"terrain_loss_db", 0.0},
                {"diffraction_loss_db", 0.0},
                {"fresnel_zone_clear", true},
                {"fresnel_clearance_percent", 100.0},
                {"obstruction_type", "none"}
            }}
        };
        
        res.set_content(response.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Terrain obstruction error: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleTerrainProfileRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Parse request parameters
        double lat1 = std::stod(req.get_param_value("lat1", "0.0"));
        double lon1 = std::stod(req.get_param_value("lon1", "0.0"));
        double lat2 = std::stod(req.get_param_value("lat2", "0.0"));
        double lon2 = std::stod(req.get_param_value("lon2", "0.0"));
        double resolution_m = std::stod(req.get_param_value("resolution_m", "30.0"));
        
        // Mock terrain profile
        nlohmann::json response = {
            {"success", true},
            {"data", {
                {"profile", {
                    {"points", nlohmann::json::array()},
                    {"max_elevation_m", 500.0},
                    {"min_elevation_m", 50.0},
                    {"average_elevation_m", 150.0},
                    {"line_of_sight_clear", true},
                    {"obstruction_height_m", 0.0},
                    {"obstruction_distance_km", 0.0}
                }},
                {"statistics", {
                    {"total_points", 100},
                    {"distance_km", 10.5},
                    {"resolution_m", resolution_m}
                }}
            }}
        };
        
        res.set_content(response.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Terrain profile error: " + std::string(e.what())), "application/json");
    }
}

void FGCom_APIServer::handleASTERGDEMStatusRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // Mock ASTER GDEM status
        nlohmann::json response = {
            {"success", true},
            {"data", {
                {"enabled", true},
                {"data_path", "/usr/share/fgcom-mumble/aster_gdem"},
                {"tiles_loaded", 25},
                {"cache_size_mb", 500},
                {"auto_download", false},
                {"download_url", "https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/"},
                {"statistics", {
                    {"tiles_loaded", 25},
                    {"profiles_calculated", 150},
                    {"cache_hits", 1200},
                    {"cache_misses", 300},
                    {"cache_hit_rate", 0.8},
                    {"memory_usage_mb", 500}
                }}
            }}
        };
        
        res.set_content(response.dump(), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("ASTER GDEM status error: " + std::string(e.what())), "application/json");
    }
}

// Advanced modulation API endpoint
void FGCom_API_Server::handleAdvancedModulationRequest(const httplib::Request& req, httplib::Response& res) {
    // Rate limiting
    if (isRateLimited()) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        std::string mode = req.get_param_value("mode");
        std::string application = req.get_param_value("application");
        
        if (application.empty()) application = "AMATEUR";
        
        nlohmann::json response;
        response["status"] = "success";
        response["mode"] = mode;
        response["application"] = application;
        
        if (mode == "DSB") {
            response["bandwidth_hz"] = 6000.0;
            response["carrier_suppressed"] = true;
            response["power_efficiency"] = 0.75;
            response["channel_spacing_hz"] = 6000.0;
        } else if (mode == "ISB") {
            response["bandwidth_hz"] = 6000.0;
            response["upper_bandwidth_hz"] = 3000.0;
            response["lower_bandwidth_hz"] = 3000.0;
            response["power_efficiency"] = 0.85;
            response["channel_spacing_hz"] = 6000.0;
        } else if (mode == "VSB") {
            response["bandwidth_hz"] = 4000.0;
            response["vestigial_bandwidth_hz"] = 1000.0;
            response["carrier_present"] = true;
            response["power_efficiency"] = 0.70;
            response["channel_spacing_hz"] = 4000.0;
        } else if (mode == "NFM") {
            response["bandwidth_hz"] = 12500.0;
            response["deviation_hz"] = 2500.0;
            response["preemphasis"] = true;
            response["squelch_required"] = true;
            response["power_efficiency"] = 0.60;
            response["channel_spacing_hz"] = 12500.0;
        } else {
            res.status = 400;
            res.set_content(createErrorResponse("Unsupported modulation mode"), "application/json");
            return;
        }
        
        res.set_content(createSuccessResponse(response.dump()), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Internal server error: " + std::string(e.what())), "application/json");
    }
}

// Maritime modulation API endpoint
void FGCom_API_Server::handleMaritimeModulationRequest(const httplib::Request& req, httplib::Response& res) {
    // Rate limiting
    if (isRateLimited()) {
        res.status = 429;
        res.set_content(createErrorResponse("Rate limit exceeded"), "application/json");
        return;
    }
    
    try {
        std::string frequency = req.get_param_value("frequency");
        std::string mode = req.get_param_value("mode");
        
        if (frequency.empty()) {
            res.status = 400;
            res.set_content(createErrorResponse("Frequency parameter required"), "application/json");
            return;
        }
        
        double freq_khz = std::stod(frequency);
        
        nlohmann::json response;
        response["status"] = "success";
        response["frequency_khz"] = freq_khz;
        response["mode"] = mode;
        response["application"] = "MARITIME";
        
        // Maritime-specific modulation characteristics
        if (mode == "DSB" || mode == "ISB") {
            response["bandwidth_hz"] = 6000.0;
            response["carrier_suppressed"] = true;
            response["power_efficiency"] = 0.75;
            response["channel_spacing_hz"] = 6000.0;
            response["squelch_required"] = false;
        } else if (mode == "NFM") {
            response["bandwidth_hz"] = 12500.0;
            response["deviation_hz"] = 2500.0;
            response["preemphasis"] = true;
            response["squelch_required"] = true;
            response["power_efficiency"] = 0.60;
            response["channel_spacing_hz"] = 12500.0;
        } else {
            response["bandwidth_hz"] = 3000.0;
            response["power_efficiency"] = 1.0;
            response["channel_spacing_hz"] = 3000.0;
        }
        
        // Maritime-specific features
        response["emergency_frequency"] = (freq_khz >= 2182.0 && freq_khz <= 2182.0);
        response["distress_frequency"] = (freq_khz >= 2182.0 && freq_khz <= 2182.0);
        response["safety_frequency"] = (freq_khz >= 2174.5 && freq_khz <= 2174.5);
        response["calling_frequency"] = (freq_khz >= 2182.0 && freq_khz <= 2182.0);
        
        res.set_content(createSuccessResponse(response.dump()), "application/json");
        total_requests++;
        
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(createErrorResponse("Internal server error: " + std::string(e.what())), "application/json");
    }
}
