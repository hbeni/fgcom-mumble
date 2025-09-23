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

#ifndef FGCOM_API_SERVER_H
#define FGCOM_API_SERVER_H

#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <functional>
#include "httplib.h"
#include "json.hpp"
#include "solar_data.h"
#include "amateur_radio.h"
#include "antenna_ground_system.h"
#include "non_amateur_hf.h"
#include "vehicle_dynamics.h"

// WebSocket client connection
struct WebSocketClient {
    int id;
    std::string endpoint;
    std::chrono::system_clock::time_point last_activity;
    bool is_active;
    
    WebSocketClient(int client_id, const std::string& ep) 
        : id(client_id), endpoint(ep), is_active(true) {
        last_activity = std::chrono::system_clock::now();
    }
};

// API request/response structures
struct PropagationRequest {
    double lat1, lon1, lat2, lon2;
    float alt1, alt2;
    float frequency_mhz;
    float power_watts;
    std::string antenna_type;
    std::string ground_type;
    std::string mode;
    std::string band;
    bool include_solar_effects;
    bool include_antenna_patterns;
    
    PropagationRequest() {
        lat1 = lon1 = lat2 = lon2 = 0.0;
        alt1 = alt2 = 0.0;
        frequency_mhz = 14.0;
        power_watts = 100.0;
        antenna_type = "vertical";
        ground_type = "average";
        mode = "SSB";
        band = "20m";
        include_solar_effects = true;
        include_antenna_patterns = true;
    }
};

struct PropagationResponse {
    float signal_quality;
    float signal_strength_db;
    float path_loss_db;
    float antenna_gain_db;
    float ground_loss_db;
    float solar_effect_db;
    float distance_km;
    float bearing_deg;
    float elevation_angle_deg;
    std::string propagation_mode;
    std::string error_message;
    bool success;
    
    PropagationResponse() {
        signal_quality = 0.0;
        signal_strength_db = 0.0;
        path_loss_db = 0.0;
        antenna_gain_db = 0.0;
        ground_loss_db = 0.0;
        solar_effect_db = 0.0;
        distance_km = 0.0;
        bearing_deg = 0.0;
        elevation_angle_deg = 0.0;
        propagation_mode = "unknown";
        error_message = "";
        success = false;
    }
};

struct BandStatusResponse {
    std::string band;
    std::string mode;
    float frequency_mhz;
    bool is_open;
    float muf_mhz;
    float luf_mhz;
    float signal_quality;
    std::string propagation_conditions;
    std::string solar_conditions;
    std::vector<std::string> active_stations;
    std::chrono::system_clock::time_point timestamp;
    
    BandStatusResponse() {
        band = "";
        mode = "";
        frequency_mhz = 0.0;
        is_open = false;
        muf_mhz = 0.0;
        luf_mhz = 0.0;
        signal_quality = 0.0;
        propagation_conditions = "";
        solar_conditions = "";
        timestamp = std::chrono::system_clock::now();
    }
};

struct AntennaPatternResponse {
    std::string antenna_name;
    float frequency_mhz;
    std::string polarization;
    std::vector<float> azimuth_angles;
    std::vector<float> elevation_angles;
    std::vector<float> gain_values;
    std::vector<float> phase_values;
    bool is_loaded;
    std::string error_message;
    
    AntennaPatternResponse() {
        antenna_name = "";
        frequency_mhz = 0.0;
        polarization = "vertical";
        is_loaded = false;
        error_message = "";
    }
};

struct GPUStatusResponse {
    bool gpu_available;
    std::string gpu_name;
    int gpu_memory_mb;
    float gpu_utilization;
    bool cuda_available;
    bool opencl_available;
    std::string error_message;
    
    GPUStatusResponse() {
        gpu_available = false;
        gpu_name = "";
        gpu_memory_mb = 0;
        gpu_utilization = 0.0;
        cuda_available = false;
        opencl_available = false;
        error_message = "";
    }
};

// API Server class
class FGCom_APIServer {
private:
    std::unique_ptr<httplib::Server> server;
    std::thread server_thread;
    std::atomic<bool> server_running;
    std::atomic<bool> websocket_enabled;
    int server_port;
    std::string server_host;
    
    // WebSocket clients
    std::vector<std::unique_ptr<WebSocketClient>> websocket_clients;
    std::mutex websocket_mutex;
    std::atomic<int> next_client_id;
    
    // Configuration
    std::map<std::string, bool> feature_flags;
    std::map<std::string, std::string> api_config;
    std::mutex config_mutex;
    
    // Rate limiting
    std::map<std::string, std::chrono::system_clock::time_point> rate_limit_map;
    std::mutex rate_limit_mutex;
    int rate_limit_requests_per_minute;
    
    // Statistics
    std::atomic<long> total_requests;
    std::atomic<long> total_websocket_connections;
    std::chrono::system_clock::time_point server_start_time;
    
    // Vehicle dynamics manager
    std::unique_ptr<FGCom_VehicleDynamicsManager> vehicle_dynamics_manager;
    
public:
    FGCom_APIServer();
    ~FGCom_APIServer();
    
    // Server management
    bool startServer(int port = 8080, const std::string& host = "0.0.0.0");
    void stopServer();
    bool isRunning() const;
    
    // Configuration management
    void loadConfiguration(const std::string& config_file);
    void setFeatureFlag(const std::string& feature, bool enabled);
    bool isFeatureEnabled(const std::string& feature) const;
    void setAPIConfig(const std::string& key, const std::string& value);
    std::string getAPIConfig(const std::string& key, const std::string& default_value = "") const;
    
    // Rate limiting
    bool checkRateLimit(const std::string& client_ip);
    void setRateLimit(int requests_per_minute);
    
    // WebSocket management
    void enableWebSocket(bool enabled);
    void broadcastToWebSocketClients(const std::string& message);
    void broadcastToWebSocketClients(const std::string& endpoint, const std::string& message);
    void removeInactiveWebSocketClients();
    
    // RESTful API endpoints
    void setupEndpoints();
    
    // Propagation endpoints
    void handlePropagationRequest(const httplib::Request& req, httplib::Response& res);
    void handlePropagationBatchRequest(const httplib::Request& req, httplib::Response& res);
    void handlePropagationHistoryRequest(const httplib::Request& req, httplib::Response& res);
    
    // Solar data endpoints
    void handleSolarDataRequest(const httplib::Request& req, httplib::Response& res);
    void handleSolarDataHistoryRequest(const httplib::Request& req, httplib::Response& res);
    void handleSolarDataForecastRequest(const httplib::Request& req, httplib::Response& res);
    
    // Band status endpoints
    void handleBandStatusRequest(const httplib::Request& req, httplib::Response& res);
    void handleBandStatusAllRequest(const httplib::Request& req, httplib::Response& res);
    void handleBandStatusHistoryRequest(const httplib::Request& req, httplib::Response& res);
    
    // Antenna pattern endpoints
    void handleAntennaPatternRequest(const httplib::Request& req, httplib::Response& res);
    void handleAntennaPatternListRequest(const httplib::Request& req, httplib::Response& res);
    void handleAntennaPatternUploadRequest(const httplib::Request& req, httplib::Response& res);
    
    // Vehicle dynamics endpoints
    void handleVehicleDynamicsRequest(const httplib::Request& req, httplib::Response& res);
    void handleVehicleListRequest(const httplib::Request& req, httplib::Response& res);
    void handleVehiclePositionRequest(const httplib::Request& req, httplib::Response& res);
    void handleVehicleAttitudeRequest(const httplib::Request& req, httplib::Response& res);
    void handleVehicleVelocityRequest(const httplib::Request& req, httplib::Response& res);
    void handleVehicleRegistrationRequest(const httplib::Request& req, httplib::Response& res);
    void handleVehicleUnregistrationRequest(const httplib::Request& req, httplib::Response& res);
    
    // Antenna rotation endpoints
    void handleAntennaRotationRequest(const httplib::Request& req, httplib::Response& res);
    void handleAntennaRotationStatusRequest(const httplib::Request& req, httplib::Response& res);
    void handleAntennaAutoTrackingRequest(const httplib::Request& req, httplib::Response& res);
    void handleAntennaListRequest(const httplib::Request& req, httplib::Response& res);
    
    // Power management endpoints
    void handlePowerManagementRequest(const httplib::Request& req, httplib::Response& res);
    void handlePowerLevelRequest(const httplib::Request& req, httplib::Response& res);
    void handlePowerEfficiencyRequest(const httplib::Request& req, httplib::Response& res);
    void handlePowerLimitingRequest(const httplib::Request& req, httplib::Response& res);
    void handlePowerOptimizationRequest(const httplib::Request& req, httplib::Response& res);
    void handlePowerSafetyRequest(const httplib::Request& req, httplib::Response& res);
    void handlePowerStatisticsRequest(const httplib::Request& req, httplib::Response& res);
    void handlePowerConfigurationRequest(const httplib::Request& req, httplib::Response& res);
    
    // Ground system endpoints
    void handleGroundSystemRequest(const httplib::Request& req, httplib::Response& res);
    void handleGroundSystemListRequest(const httplib::Request& req, httplib::Response& res);
    void handleGroundSystemCalculateRequest(const httplib::Request& req, httplib::Response& res);
    
    // GPU status endpoints
    void handleGPUStatusRequest(const httplib::Request& req, httplib::Response& res);
    void handleGPUUtilizationRequest(const httplib::Request& req, httplib::Response& res);
    
    // Configuration endpoints
    void handleConfigRequest(const httplib::Request& req, httplib::Response& res);
    void handleConfigUpdateRequest(const httplib::Request& req, httplib::Response& res);
    void handleFeatureFlagsRequest(const httplib::Request& req, httplib::Response& res);
    
    // Statistics endpoints
    void handleStatsRequest(const httplib::Request& req, httplib::Response& res);
    void handleHealthCheckRequest(const httplib::Request& req, httplib::Response& res);
    
    // WebSocket endpoints
    void handleWebSocketConnection(const httplib::Request& req, httplib::Response& res);
    void handleWebSocketMessage(const std::string& message, int client_id);
    
    // Utility functions
    std::string getClientIP(const httplib::Request& req) const;
    std::string createErrorResponse(const std::string& error_message, int error_code = 400) const;
    std::string createSuccessResponse(const nlohmann::json& data) const;
    
    // JSON conversion functions
    nlohmann::json propagationRequestToJSON(const PropagationRequest& req) const;
    nlohmann::json propagationResponseToJSON(const PropagationResponse& resp) const;
    nlohmann::json bandStatusResponseToJSON(const BandStatusResponse& resp) const;
    nlohmann::json antennaPatternResponseToJSON(const AntennaPatternResponse& resp) const;
    nlohmann::json gpuStatusResponseToJSON(const GPUStatusResponse& resp) const;
    nlohmann::json solarConditionsToJSON(const fgcom_solar_conditions& solar) const;
    
    PropagationRequest parsePropagationRequest(const nlohmann::json& json) const;
    
    // Real-time update functions
    void broadcastPropagationUpdate(const fgcom_solar_conditions& solar);
    void broadcastBandStatusUpdate(const std::string& band, const BandStatusResponse& status);
    void broadcastAntennaPatternUpdate(const std::string& antenna_name, const AntennaPatternResponse& pattern);
    
    // Statistics
    long getTotalRequests() const;
    long getTotalWebSocketConnections() const;
    std::chrono::system_clock::time_point getServerStartTime() const;
    std::map<std::string, std::string> getServerStats() const;
    
private:
    // Internal helper functions
    void serverThreadFunction();
    void setupCORS();
    void setupLogging();
    void setupErrorHandling();
    bool validateAPIKey(const httplib::Request& req) const;
    std::string generateAPIKey() const;
    void logRequest(const httplib::Request& req, const httplib::Response& res);
    void cleanup();
};

// API Client helper class for testing
class FGCom_APIClient {
private:
    std::string base_url;
    std::string api_key;
    std::unique_ptr<httplib::Client> client;
    
public:
    FGCom_APIClient(const std::string& url, const std::string& key = "");
    
    // Propagation API calls
    PropagationResponse getPropagation(const PropagationRequest& req);
    std::vector<PropagationResponse> getPropagationBatch(const std::vector<PropagationRequest>& requests);
    
    // Solar data API calls
    fgcom_solar_conditions getSolarData();
    std::vector<fgcom_solar_conditions> getSolarDataHistory(int hours = 24);
    
    // Band status API calls
    BandStatusResponse getBandStatus(const std::string& band, const std::string& mode = "");
    std::vector<BandStatusResponse> getAllBandStatus();
    
    // Antenna pattern API calls
    AntennaPatternResponse getAntennaPattern(const std::string& antenna_name, float frequency_mhz);
    std::vector<std::string> getAvailableAntennaPatterns();
    
    // Ground system API calls
    GroundSystem getGroundSystem(const std::string& system_name);
    std::vector<std::string> getAvailableGroundSystems();
    
    // GPU status API calls
    GPUStatusResponse getGPUStatus();
    
    // Configuration API calls
    std::map<std::string, std::string> getConfiguration();
    bool updateConfiguration(const std::map<std::string, std::string>& config);
    std::map<std::string, bool> getFeatureFlags();
    bool setFeatureFlag(const std::string& feature, bool enabled);
    
    // Statistics API calls
    std::map<std::string, std::string> getServerStats();
    bool healthCheck();
    
private:
    nlohmann::json makeRequest(const std::string& endpoint, const nlohmann::json& data = nlohmann::json::object());
    void setHeaders(httplib::Headers& headers);
};

#endif // FGCOM_API_SERVER_H
