#!/usr/bin/env luajit
--[[
 * @file fake_moon_api.lua
 * @brief Fake Moon Placement API for FGcom-Mumble
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file implements a comprehensive API for placing and managing fake moons
 * in the FGcom-Mumble simulation system. It provides realistic orbital mechanics,
 * visibility calculations, and communication effects for artificial moons.
 * 
 * Features:
 * - Place fake moons with custom orbital parameters
 * - Realistic orbital mechanics simulation
 * - Moon visibility and communication effects
 * - Doppler shift calculations for moon communications
 * - Integration with existing satellite systems
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/API_REFERENCE_COMPLETE.md
]]

local json = require("dkjson")
local socket = require("socket")
local math = math
local os = os
local string = string
local table = table

-- Moon API Configuration
local MOON_API_CONFIG = {
    port = 8081,
    host = "0.0.0.0",
    max_moons = 50,
    default_altitude = 384400, -- km (Earth-Moon distance)
    default_radius = 1737.4,   -- km (Moon radius)
    orbital_period = 27.3,     -- days (sidereal month)
    max_communication_range = 500000, -- km
    doppler_compensation = true,
    atmospheric_effects = true,
    signal_degradation = true
}

-- Fake Moon Database
local fake_moons = {}
local moon_counter = 0

-- Moon orbital mechanics
local function calculate_moon_position(moon, time_offset)
    local t = os.time() + (time_offset or 0)
    local days_since_epoch = (t - 946684800) / 86400 -- Days since 2000-01-01
    
    -- Simplified orbital mechanics for fake moons
    local mean_anomaly = (moon.orbital_period and (360 * days_since_epoch / moon.orbital_period) or 0) % 360
    local true_anomaly = mean_anomaly + moon.eccentricity * 57.3 * math.sin(math.rad(mean_anomaly))
    
    -- Calculate position in orbital plane
    local r = moon.semi_major_axis * (1 - moon.eccentricity^2) / (1 + moon.eccentricity * math.cos(math.rad(true_anomaly)))
    local x = r * math.cos(math.rad(true_anomaly))
    local y = r * math.sin(math.rad(true_anomaly))
    
    -- Apply orbital inclination
    local inclination_rad = math.rad(moon.inclination or 0)
    local z = y * math.sin(inclination_rad)
    y = y * math.cos(inclination_rad)
    
    -- Apply longitude of ascending node
    local node_rad = math.rad(moon.longitude_of_ascending_node or 0)
    local cos_node = math.cos(node_rad)
    local sin_node = math.sin(node_rad)
    local x_final = x * cos_node - y * sin_node
    local y_final = x * sin_node + y * cos_node
    
    return {
        x = x_final,
        y = y_final,
        z = z,
        distance = math.sqrt(x_final^2 + y_final^2 + z^2),
        true_anomaly = true_anomaly
    }
end

-- Calculate moon visibility from ground station
local function calculate_moon_visibility(moon, ground_station)
    local pos = calculate_moon_position(moon)
    local earth_radius = 6371 -- km
    
    -- Calculate elevation angle
    local distance_to_moon = pos.distance
    local elevation = math.deg(math.asin((distance_to_moon^2 - earth_radius^2) / (2 * earth_radius * distance_to_moon)))
    
    -- Calculate azimuth (simplified)
    local azimuth = math.deg(math.atan2(pos.y, pos.x))
    if azimuth < 0 then azimuth = azimuth + 360 end
    
    return {
        visible = elevation > (moon.minimum_elevation or 5),
        elevation = elevation,
        azimuth = azimuth,
        distance = distance_to_moon,
        position = pos
    }
end

-- Calculate Doppler shift for moon communication
local function calculate_doppler_shift(moon, ground_station, frequency)
    local pos1 = calculate_moon_position(moon, 0)
    local pos2 = calculate_moon_position(moon, 1) -- 1 second later
    
    local velocity = math.sqrt((pos2.x - pos1.x)^2 + (pos2.y - pos1.y)^2 + (pos2.z - pos1.z)^2)
    local doppler_shift = (velocity / 299792.458) * frequency -- c = 299792.458 km/s
    
    return doppler_shift
end

-- API Endpoints
local function handle_add_moon(request_data)
    moon_counter = moon_counter + 1
    local moon_id = "FAKE-MOON-" .. moon_counter
    
    local moon = {
        id = moon_id,
        name = request_data.name or moon_id,
        type = request_data.type or "COMMUNICATION",
        mode = request_data.mode or "REFLECTOR",
        
        -- Orbital parameters
        semi_major_axis = request_data.orbital_parameters.semi_major_axis or MOON_API_CONFIG.default_altitude,
        eccentricity = request_data.orbital_parameters.eccentricity or 0.0,
        inclination = request_data.orbital_parameters.inclination or 0.0,
        longitude_of_ascending_node = request_data.orbital_parameters.longitude_of_ascending_node or 0.0,
        orbital_period = request_data.orbital_parameters.orbital_period or MOON_API_CONFIG.orbital_period,
        
        -- Physical parameters
        radius = request_data.physical_parameters.radius or MOON_API_CONFIG.default_radius,
        mass = request_data.physical_parameters.mass or 7.342e22, -- kg (Moon mass)
        albedo = request_data.physical_parameters.albedo or 0.136,
        
        -- Communication parameters
        frequencies = request_data.frequencies or {
            uplink = 145.900,
            downlink = 435.800
        },
        power = request_data.power or 100, -- watts
        antenna_gain = request_data.antenna_gain or 10, -- dBi
        
        -- Visibility parameters
        minimum_elevation = request_data.minimum_elevation or 5,
        maximum_range = request_data.maximum_range or MOON_API_CONFIG.max_communication_range,
        
        -- Simulation effects
        doppler_compensation = request_data.doppler_compensation ~= false,
        atmospheric_effects = request_data.atmospheric_effects ~= false,
        signal_degradation = request_data.signal_degradation ~= false,
        
        -- Metadata
        created_at = os.time(),
        active = true
    }
    
    fake_moons[moon_id] = moon
    
    return {
        success = true,
        moon = {
            id = moon.id,
            name = moon.name,
            type = moon.type,
            mode = moon.mode,
            orbital_parameters = {
                semi_major_axis = moon.semi_major_axis,
                eccentricity = moon.eccentricity,
                inclination = moon.inclination,
                longitude_of_ascending_node = moon.longitude_of_ascending_node,
                orbital_period = moon.orbital_period
            },
            physical_parameters = {
                radius = moon.radius,
                mass = moon.mass,
                albedo = moon.albedo
            },
            frequencies = moon.frequencies,
            power = moon.power,
            antenna_gain = moon.antenna_gain,
            minimum_elevation = moon.minimum_elevation,
            maximum_range = moon.maximum_range,
            simulation_effects = {
                doppler_compensation = moon.doppler_compensation,
                atmospheric_effects = moon.atmospheric_effects,
                signal_degradation = moon.signal_degradation
            },
            active = moon.active,
            created_at = moon.created_at
        }
    }
end

local function handle_get_moon_position(moon_id, ground_station)
    local moon = fake_moons[moon_id]
    if not moon then
        return {
            success = false,
            error = "Moon not found: " .. moon_id
        }
    end
    
    local visibility = calculate_moon_visibility(moon, ground_station)
    local doppler_shift = 0
    
    if moon.doppler_compensation and ground_station then
        doppler_shift = calculate_doppler_shift(moon, ground_station, moon.frequencies.uplink)
    end
    
    return {
        success = true,
        moon_id = moon_id,
        position = {
            x = visibility.position.x,
            y = visibility.position.y,
            z = visibility.position.z,
            distance = visibility.distance,
            true_anomaly = visibility.position.true_anomaly
        },
        visibility = {
            visible = visibility.visible,
            elevation = visibility.elevation,
            azimuth = visibility.azimuth,
            distance = visibility.distance
        },
        doppler_shift = doppler_shift,
        timestamp = os.time()
    }
end

local function handle_simulate_communication(moon_id, ground_station, audio_data, effects)
    local moon = fake_moons[moon_id]
    if not moon then
        return {
            success = false,
            error = "Moon not found: " .. moon_id
        }
    end
    
    local visibility = calculate_moon_visibility(moon, ground_station)
    if not visibility.visible then
        return {
            success = false,
            error = "Moon not visible from ground station"
        }
    end
    
    local doppler_shift = 0
    if moon.doppler_compensation and effects.doppler_shift then
        doppler_shift = calculate_doppler_shift(moon, ground_station, moon.frequencies.uplink)
    end
    
    -- Calculate signal quality based on distance and effects
    local signal_quality = 1.0
    if effects.signal_degradation then
        signal_quality = signal_quality * (1 - (visibility.distance / moon.maximum_range))
    end
    
    if effects.atmospheric_effects then
        signal_quality = signal_quality * (1 - (90 - visibility.elevation) / 90 * 0.1)
    end
    
    signal_quality = math.max(0.1, math.min(1.0, signal_quality))
    
    return {
        success = true,
        moon_id = moon_id,
        position = {
            x = visibility.position.x,
            y = visibility.position.y,
            z = visibility.position.z,
            distance = visibility.distance,
            elevation = visibility.elevation,
            azimuth = visibility.azimuth
        },
        communication = {
            doppler_shift = doppler_shift,
            signal_quality = signal_quality,
            signal_strength = 20 * math.log10(signal_quality) - 100, -- dBm
            communication_quality = signal_quality,
            uplink_frequency = moon.frequencies.uplink + doppler_shift,
            downlink_frequency = moon.frequencies.downlink + doppler_shift
        },
        simulated_audio = audio_data, -- In real implementation, this would be processed
        timestamp = os.time()
    }
end

local function handle_list_moons()
    local moon_list = {}
    for id, moon in pairs(fake_moons) do
        table.insert(moon_list, {
            id = moon.id,
            name = moon.name,
            type = moon.type,
            mode = moon.mode,
            active = moon.active,
            created_at = moon.created_at
        })
    end
    
    return {
        success = true,
        moons = moon_list,
        total_moons = #moon_list,
        max_moons = MOON_API_CONFIG.max_moons
    }
end

local function handle_remove_moon(moon_id)
    if not fake_moons[moon_id] then
        return {
            success = false,
            error = "Moon not found: " .. moon_id
        }
    end
    
    fake_moons[moon_id] = nil
    
    return {
        success = true,
        message = "Moon removed: " .. moon_id
    }
end

-- HTTP Server Implementation
local function create_http_response(status_code, content_type, body)
    local response = "HTTP/1.1 " .. status_code .. "\r\n"
    response = response .. "Content-Type: " .. content_type .. "\r\n"
    response = response .. "Content-Length: " .. string.len(body) .. "\r\n"
    response = response .. "Access-Control-Allow-Origin: *\r\n"
    response = response .. "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
    response = response .. "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
    response = response .. "\r\n"
    response = response .. body
    return response
end

local function parse_http_request(request)
    local lines = {}
    for line in string.gmatch(request, "[^\r\n]+") do
        table.insert(lines, line)
    end
    
    if #lines == 0 then return nil end
    
    local method, path, version = string.match(lines[1], "(%S+)%s+(%S+)%s+(%S+)")
    local headers = {}
    local body_start = 2
    
    for i = 2, #lines do
        if lines[i] == "" then
            body_start = i + 1
            break
        end
        local key, value = string.match(lines[i], "([^:]+):%s*(.+)")
        if key and value then
            headers[string.lower(key)] = value
        end
    end
    
    local body = ""
    if body_start <= #lines then
        body = table.concat(lines, "\n", body_start)
    end
    
    return {
        method = method,
        path = path,
        version = version,
        headers = headers,
        body = body
    }
end

local function handle_request(request)
    local parsed = parse_http_request(request)
    if not parsed then
        return create_http_response(400, "text/plain", "Bad Request")
    end
    
    local method = parsed.method
    local path = parsed.path
    local body = parsed.body
    
    -- Handle CORS preflight
    if method == "OPTIONS" then
        return create_http_response(200, "text/plain", "")
    end
    
    local response_data = {}
    
    if method == "POST" and path == "/api/v1/moon/add" then
        local request_data = json.decode(body)
        if request_data then
            response_data = handle_add_moon(request_data)
        else
            response_data = {success = false, error = "Invalid JSON"}
        end
        
    elseif method == "GET" and string.match(path, "^/api/v1/moon/position/([^/]+)$") then
        local moon_id = string.match(path, "^/api/v1/moon/position/([^/]+)$")
        local ground_station = {
            latitude = 40.7128,
            longitude = -74.0060,
            altitude = 0.0
        }
        response_data = handle_get_moon_position(moon_id, ground_station)
        
    elseif method == "POST" and string.match(path, "^/api/v1/moon/simulate/([^/]+)$") then
        local moon_id = string.match(path, "^/api/v1/moon/simulate/([^/]+)$")
        local request_data = json.decode(body)
        if request_data then
            response_data = handle_simulate_communication(moon_id, request_data.ground_station, request_data.audio_data, request_data.effects)
        else
            response_data = {success = false, error = "Invalid JSON"}
        end
        
    elseif method == "GET" and path == "/api/v1/moon/list" then
        response_data = handle_list_moons()
        
    elseif method == "DELETE" and string.match(path, "^/api/v1/moon/remove/([^/]+)$") then
        local moon_id = string.match(path, "^/api/v1/moon/remove/([^/]+)$")
        response_data = handle_remove_moon(moon_id)
        
    else
        response_data = {success = false, error = "Endpoint not found"}
    end
    
    local response_body = json.encode(response_data)
    return create_http_response(200, "application/json", response_body)
end

-- Main server loop
local function start_server()
    local server = socket.bind(MOON_API_CONFIG.host, MOON_API_CONFIG.port)
    if not server then
        print("Error: Could not bind to " .. MOON_API_CONFIG.host .. ":" .. MOON_API_CONFIG.port)
        return
    end
    
    server:settimeout(1) -- 1 second timeout
    print("Fake Moon API Server started on " .. MOON_API_CONFIG.host .. ":" .. MOON_API_CONFIG.port)
    print("Available endpoints:")
    print("  POST /api/v1/moon/add - Add a fake moon")
    print("  GET  /api/v1/moon/position/{id} - Get moon position")
    print("  POST /api/v1/moon/simulate/{id} - Simulate communication")
    print("  GET  /api/v1/moon/list - List all moons")
    print("  DELETE /api/v1/moon/remove/{id} - Remove a moon")
    
    while true do
        local client = server:accept()
        if client then
            client:settimeout(5)
            local request = client:receive("*a")
            if request then
                local response = handle_request(request)
                client:send(response)
            end
            client:close()
        end
        socket.sleep(0.01) -- Small delay to prevent CPU spinning
    end
end

-- Start the server if this script is run directly
if arg and arg[0] and string.match(arg[0], "fake_moon_api%.lua$") then
    start_server()
end

-- Export functions for use as a module
return {
    handle_add_moon = handle_add_moon,
    handle_get_moon_position = handle_get_moon_position,
    handle_simulate_communication = handle_simulate_communication,
    handle_list_moons = handle_list_moons,
    handle_remove_moon = handle_remove_moon,
    start_server = start_server,
    MOON_API_CONFIG = MOON_API_CONFIG
}
