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

#include "globalVars.h"
#include <mutex>
#include <map>
#include <vector>

struct fgcom_config fgcom_cfg;
std::mutex fgcom_localcfg_mtx;
std::map<int, fgcom_client> fgcom_local_client;
std::map<mumble_userid_t, std::map<int, fgcom_client> > fgcom_remote_clients;
std::mutex fgcom_remotecfg_mtx;
std::vector<mumble_channelid_t> fgcom_specialChannelID;
std::vector<CachedRadioInfo> cached_radio_infos;
std::mutex cached_radio_infos_mtx;

