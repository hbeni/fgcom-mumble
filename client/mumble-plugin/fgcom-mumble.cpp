/*******************************************************************//**
 * @file        fgcom-mumble.cpp
 * @brief       Main file of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * @authors    	Benedikt Hallinger & mill-j
 * @copyright   (C) 2020 - 2021 under GNU GPL v3 
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
 *
 * Mumble API:
 * Copyright 2019-2020 The Mumble Developers. All rights reserved.
 * Use of this source code is governed by a BSD-style license
 * that can be found in the LICENSE file at the root of the
 * Mumble source tree or at <https://www.mumble.info/LICENSE>.
 */
#include "fgcom-mumble.h"
#include "mumble/plugin/MumblePlugin.h"
#include <iostream>


/**
 * Fired when the server is synchronized after connection
 */
void FgcomPlugin::onServerSynchronized(mumble_connection_t connection) noexcept {
	try {
		pluginLog("Server has finished synchronizing (ServerConnection: " + std::to_string(connection) + ")");
		
		//Get Users
		MumbleArray users = m_api.getAllUsers(connection);
		std::string msg;
		for(int a = 0; a < users.size();a++) {
			msg = m_api.getUserName(connection, users[a]).c_str();
			pluginLog("Found User " + msg);
		}
		
		//Get Channels
		MumbleArray channels = 	m_api.getAllChannels(connection);
		bool ChannelFound = false;
		for(int a = 0; a < channels.size();a++) {
			msg = m_api.getChannelName(connection, channels[a]).c_str();
			pluginLog("Found Channel " + msg);
			if(m_api.getChannelName(connection, channels[a]) == "fgcom-mumble")
				ChannelFound = true;
		}
		
		if(ChannelFound)
			pluginLog("Special Channel Found!");
		else 
			pluginLog("Special Channel Not Found!");
		
	} catch (const MumbleAPIException &e) {
		std::cerr << "onServerSynchronized: " << e.what() << " (ErrorCode " << e.errorCode() << ")" << std::endl;
	}
}

/**
 * Fired when the server is disconnected
 */
void FgcomPlugin::onServerDisconnected(mumble_connection_t connection) noexcept {
	pluginLog("Disconnected from server-connection with ID " + std::to_string(connection));
}

/**
 * Fired when the server is disconnected
 */
void FgcomPlugin::onServerConnected(mumble_connection_t connection) noexcept {
	pluginLog("Established server-connection with ID " + std::to_string(connection));
}
/**
 * Fired when the user exits channel
 */
void FgcomPlugin::onChannelExited(mumble_connection_t connection, mumble_userid_t userID, mumble_channelid_t channelID ) noexcept {
	pluginDbg("User with ID "+ std::to_string(userID) + " has left channel with ID " + std::to_string(channelID) + ". (ServerConnection: " + std::to_string(connection) + ")");
}

/**
 * Fired when the user enters channel
 */
void FgcomPlugin::onChannelEntered (mumble_connection_t connection, mumble_userid_t userID, 
		mumble_channelid_t  previousChannelID, mumble_channelid_t newChannelID) noexcept {
	
	pluginDbg("User with ID "+ std::to_string(userID) + " has joined channel with ID " + std::to_string(newChannelID) + ", coming from "+ std::to_string(previousChannelID) +". (ServerConnection: " + std::to_string(connection) + ")");
}

/**
 * Prints log entry to logfile or stdout
 * @todo Add timestamp, logfile, and maybe move elsewhere
 */
void FgcomPlugin::pluginLog(std::string log) {
	std::cout<<"Fgcom2 [LOG]: "<<log<<std::endl;
}

/**
 * Prints debug entry to stdout
 * @todo Add timestamp, and maybe move elsewhere
 */
void FgcomPlugin::pluginDbg(std::string log) {
	std::cout<<"Fgcom2 [DGB]: "<<log<<std::endl;
}

/**
 * The entry point for the plugin.
 */
MumblePlugin &MumblePlugin::getPlugin() noexcept {
	static FgcomPlugin plugin;
	return plugin;
}
