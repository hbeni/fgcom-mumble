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
#include "shared_data.h"
#include <algorithm>

// Global shared data instance
std::unique_ptr<FGCom_SharedData> g_shared_data = nullptr;

FGCom_SharedData::FGCom_SharedData() 
    : udp_server_running_(false)
    , udp_client_running_(false)
    , gc_thread_running_(false)
    , debug_thread_running_(false) {
}

FGCom_SharedData::~FGCom_SharedData() {
    clearAllData();
}

// Local client access
void FGCom_SharedData::addLocalClient(int id, const fgcom_client& client) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    local_clients_[id] = client;
}

fgcom_client FGCom_SharedData::getLocalClient(int id) const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    auto it = local_clients_.find(id);
    if (it != local_clients_.end()) {
        return it->second;
    }
    return fgcom_client(); // Return default constructed client
}

void FGCom_SharedData::updateLocalClient(int id, const fgcom_client& client) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    local_clients_[id] = client;
}

size_t FGCom_SharedData::getLocalClientCount() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return local_clients_.size();
}

void FGCom_SharedData::removeLocalClient(int id) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    local_clients_.erase(id);
}

// Remote client access
void FGCom_SharedData::addRemoteClient(mumble_userid_t userid, int radio_id, const fgcom_client& client) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    remote_clients_[userid][radio_id] = client;
}

fgcom_client FGCom_SharedData::getRemoteClient(mumble_userid_t userid, int radio_id) const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    auto user_it = remote_clients_.find(userid);
    if (user_it != remote_clients_.end()) {
        auto radio_it = user_it->second.find(radio_id);
        if (radio_it != user_it->second.end()) {
            return radio_it->second;
        }
    }
    return fgcom_client(); // Return default constructed client
}

void FGCom_SharedData::updateRemoteClient(mumble_userid_t userid, int radio_id, const fgcom_client& client) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    remote_clients_[userid][radio_id] = client;
}

void FGCom_SharedData::removeRemoteClient(mumble_userid_t userid, int radio_id) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    auto user_it = remote_clients_.find(userid);
    if (user_it != remote_clients_.end()) {
        user_it->second.erase(radio_id);
        if (user_it->second.empty()) {
            remote_clients_.erase(user_it);
        }
    }
}

std::map<int, fgcom_client> FGCom_SharedData::getRemoteClientsForUser(mumble_userid_t userid) const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    auto user_it = remote_clients_.find(userid);
    if (user_it != remote_clients_.end()) {
        return user_it->second;
    }
    return std::map<int, fgcom_client>();
}

// Server state management
void FGCom_SharedData::setUdpServerRunning(bool running) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    udp_server_running_ = running;
}

bool FGCom_SharedData::isUdpServerRunning() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return udp_server_running_;
}

void FGCom_SharedData::setUdpClientRunning(bool running) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    udp_client_running_ = running;
}

bool FGCom_SharedData::isUdpClientRunning() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return udp_client_running_;
}

void FGCom_SharedData::setGcThreadRunning(bool running) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    gc_thread_running_ = running;
}

bool FGCom_SharedData::isGcThreadRunning() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return gc_thread_running_;
}

void FGCom_SharedData::setDebugThreadRunning(bool running) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    debug_thread_running_ = running;
}

bool FGCom_SharedData::isDebugThreadRunning() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return debug_thread_running_;
}

// Configuration access
void FGCom_SharedData::setConfigValue(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    config_data_[key] = value;
}

std::string FGCom_SharedData::getConfigValue(const std::string& key, const std::string& default_value) const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    auto it = config_data_.find(key);
    if (it != config_data_.end()) {
        return it->second;
    }
    return default_value;
}

bool FGCom_SharedData::hasConfigValue(const std::string& key) const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return config_data_.find(key) != config_data_.end();
}

// Thread-safe operations
void FGCom_SharedData::lock() const {
    data_mutex_.lock();
}

void FGCom_SharedData::unlock() const {
    data_mutex_.unlock();
}

// Cleanup
void FGCom_SharedData::clearAllData() {
    std::lock_guard<std::mutex> lock(data_mutex_);
    local_clients_.clear();
    remote_clients_.clear();
    config_data_.clear();
    udp_server_running_ = false;
    udp_client_running_ = false;
    gc_thread_running_ = false;
    debug_thread_running_ = false;
}

void FGCom_SharedData::clearLocalClients() {
    std::lock_guard<std::mutex> lock(data_mutex_);
    local_clients_.clear();
}

void FGCom_SharedData::clearRemoteClients() {
    std::lock_guard<std::mutex> lock(data_mutex_);
    remote_clients_.clear();
}
