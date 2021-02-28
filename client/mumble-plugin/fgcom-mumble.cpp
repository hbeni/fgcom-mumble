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
 * The entry point for the plugin.
 */
MumblePlugin &MumblePlugin::getPlugin() noexcept {
	static FgcomPlugin plugin;
	return plugin;
}


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
	//See if connection is synchronized
	if(m_api.isConnectionSynchronized(connection)) {
		//See if local user connected
		if(userID == m_api.getLocalUserID(connection)) {
			pluginDbg("Local Connected");
			//See if this the the special channel
			if(m_api.getChannelName(connection,channelID) == specialChannel) {
				///<@todo add a ping to server to free if no client conneced
				pluginDbg("Stopping server");
				udpServerRunning = false;
				fgcom_readThread.join();
			}
		}
	}
	pluginDbg("User with ID "+ std::to_string(userID) + " has left channel with ID " + std::to_string(channelID) + ". (ServerConnection: " + std::to_string(connection) + ")");
}

/**
 * Fired when the user enters channel
 */
void FgcomPlugin::onChannelEntered (mumble_connection_t connection, mumble_userid_t userID, 
		mumble_channelid_t  previousChannelID, mumble_channelid_t newChannelID) noexcept {
	
	//See if connection is synchronized
	if(m_api.isConnectionSynchronized(connection)) {
		//See if local user connected
		if(userID == m_api.getLocalUserID(connection)) {
			pluginDbg("I Connected");
			//See if this the the special channel
			if(m_api.getChannelName(connection,newChannelID) == specialChannel) {
				pluginDbg("Ok start server");
				udpServerRunning = true;
				fgcom_readThread = std::thread(&FgcomPlugin::fgcom_spawnUDPServer, this);
	
			}
		}
	}
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
	std::cout<<"Fgcom2 [DBG]: "<<log<<std::endl;
}

/**
 * @brief Creates a udp server to retrieve data from flight sim or other 
 * data source.
 */
void FgcomPlugin::fgcom_spawnUDPServer() {
	
	struct sockaddr_in localSocket, remoteSocket;
	unsigned int recv_len,slen= sizeof(remoteSocket);
	int s, i = -1;
	char buf[BUFLEN];
	
	
	//create a UDP socket
	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		pluginLog("Create Socket Failed!");
		return;
	}
	
	// zero out the structure
	memset((char *) &localSocket, 0, sizeof(localSocket));
	
	localSocket.sin_family = AF_INET;
	localSocket.sin_port = htons(PORT);
	localSocket.sin_addr.s_addr = htonl(INADDR_ANY); 
	
	//Allow us to reconnect with same port
	int reuse = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        pluginLog("setsockopt(SO_REUSEADDR) failed");

	
	///bind socket to port @todo add varible port on failure 
	if( bind(s , (struct sockaddr*)&localSocket, sizeof(localSocket) ) == -1) {
		pluginLog("Bind Socket To Port Failed!");
		return;
	}
	
	
	std::string preData, curBuffer;
	std::vector<std::string> splitBuffer, finalBuffer;
	fgcom_keyvalue udpData;
	unsigned int c = 0;
	fgcom_radio radioBuffer;
	fgcom_location locBuffer;
	
	while(udpServerRunning) {		
		//receive data, this is a blocking call
		recv_len = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &remoteSocket, &slen);
		curBuffer = buf;
		//If nothing changed lets just skip parsing
		if(preData == curBuffer)
			continue;

		//std::cout<<"Received packet from "<<inet_ntoa(remoteSocket.sin_addr)<<":"<<ntohs(remoteSocket.sin_port)<<std::endl;
		pluginDbg(curBuffer);
		udpData.clear();
		
		///@todo Add check to make sure message was valid		
		splitBuffer = udpData.splitStrings(curBuffer,",");
		
		//pluginDbg(splitBuffer[0]);
		
		for(c = 0; c < splitBuffer.size(); c++) {
			///@todo Add check to make sure message was valid
			finalBuffer = udpData.splitStrings(splitBuffer[c],"=");
			pluginDbg(finalBuffer[0]);
			if(finalBuffer.size() == 2)
				udpData.add(finalBuffer[0], finalBuffer[1]);
		}
			
		//Do something with data
		
		//Callsign
		localUser.setCallsign(udpData.getValue("CALLSIGN"));
		
		//Location
		locBuffer.set(udpData.getFloat("LON"), udpData.getFloat("LAT"),udpData.getFloat("HGT"));
		localUser.setLocation(locBuffer);
		
		//Radios
		int r = 1;
		
		while(true) {
			if(udpData.getValue("COM" + std::to_string(r) + "_PTT") != "Error!") {
				pluginDbg("Found Radio " + std::to_string(r));
				fgcom_radio radio;
				
				if(udpData.getInt("COM" + std::to_string(r) + "_PBT") == 1)
					radio.setPowered(true);
				else
					radio.setPowered(false);
				
				if(udpData.getInt("COM" + std::to_string(r) + "_PTT") == 1)
					radio.setPTT(true);
				else
					radio.setPTT(false);
				
				radio.setFrequency(udpData.getFloat("COM" + std::to_string(r) + "_FRQ"));	
				radio.setDialedFrequency(udpData.getValue("COM" + std::to_string(r) + "_FRQ"));
				radio.setVolume(udpData.getFloat("COM" + std::to_string(r) + "_VOL"));	
				radio.setWatts(udpData.getFloat("COM" + std::to_string(r) + "_PWR"));			
				radio.setSquelch(udpData.getFloat("COM" + std::to_string(r) + "_SQC"));
				radio.setChannelWidth(udpData.getFloat("COM" + std::to_string(r) + "_CWKHZ"));
				
				localUser.setRadio(radio, r);
			}
			else
				break;
			r++;
		}
		
		
		
		preData = buf;
	}
	pluginDbg("Server loop done!");
	return;
}
