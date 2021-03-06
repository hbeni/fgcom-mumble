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
 * Mumble API:B
 * Copyright 2019-2020 The Mumble Developers. All rights reserved.
 * Use of this source code is governed by a BSD-style license
 * that can be found in the LICENSE file at the root of the
 * Mumble source tree or at <https://www.mumble.info/LICENSE>.
 */
#include "fgcom-mumble.h"
#include "mumble/plugin/MumblePlugin.h"
#include <iostream>

#define NOTIFYPINGINTERVAL 10000

/**
 * The entry point for the plugin.
 */
MumblePlugin &MumblePlugin::getPlugin() noexcept {
	static FgcomPlugin plugin;
	return plugin;
}


/**
 * Fired when the server is synchronized after conBnection
 */
void FgcomPlugin::onServerSynchronized(mumble_connection_t connection) noexcept {
	try {
		pluginLog("Server has finished synchronizing (ServerConnection: " + std::to_string(connection) + ")");
		
		//Get Channels
		MumbleArray channels = 	m_api.getAllChannels(connection);
		bool ChannelFound = false;
		for(int a = 0; a < channels.size();a++) {
			std::string msg = m_api.getChannelName(connection, channels[a]).c_str();
			pluginLog("Found Channel " + msg);
			if(m_api.getChannelName(connection, channels[a]) == "fgcom-mumble")
				ChannelFound = true;
		}
		
		if(ChannelFound)
			pluginLog("Special Channel Found!");
		else 
			pluginLog("Special Channel Not Found!");
			
		//Set our ID
		localUser.setUid(m_api.getLocalUserID(m_api.getActiveServerConnection()));
		
		pluginDbg("Ok start server");
		udpServerRunning = true;
		fgcom_readThread = std::thread(&FgcomPlugin::fgcom_spawnUDPServer, this);
		
	} catch (const MumbleAPIException &e) {
		std::cerr << "onServerSynchronized: " << e.what() << " (ErrorCode " << e.errorCode() << ")" << std::endl;
	}
}

/**
 * Fired when the server is disconnected
 */
void FgcomPlugin::onServerDisconnected(mumble_connection_t connection) noexcept {
	pluginLog("Disconnected from server-connection with ID " + std::to_string(connection));
	
	///<@todo add a ping to server to free if no client conneced
	pluginDbg("Stopping server");
	udpServerRunning = false;
	fgcom_readThread.join();
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
		if(m_api.getChannelName(connection,channelID) == specialChannel) {
			pluginDbg("Local Connected");
			//See if this the the special channel
			if(userID == m_api.getLocalUserID(connection)) {
				//Restore Transmission Mode
				mumble_error_t merr;
				m_api.requestLocalUserTransmissionMode(fgcom_prevTransmissionMode);
				m_api.requestMicrophoneActivationOvewrite(false);
				m_api.log("Restored Transmission Mode");
			}
			else {
				///@todo Remove user from array
				for(unsigned int a = 0; a < remoteUsers.size();a++) {
					if(remoteUsers[a].getUid() == userID) {
						pluginDbg("Removing User: " + std::to_string(userID));
						remoteUsers.erase(remoteUsers.begin() + a);
						break;
					}
				}
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
		//See if this the the special channel
		if(m_api.getChannelName(connection,newChannelID) == specialChannel) {
			//See if local user connected
			if(userID == m_api.getLocalUserID(connection)) {
				pluginDbg("Local Connected");
				//Send data to other plugins
				MumbleArray channelUsers = m_api.getUsersInChannel(connection,newChannelID);
				
				for(int a = 0; a < channelUsers.size();a++) {
					if(channelUsers[a] == m_api.getLocalUserID(connection)) {
						pluginDbg("Skipping Local User");
						continue;
					}
					std::string msg = m_api.getUserName(connection, channelUsers[a]).c_str();
					fgcom_identity temp;
					
					temp.setUid(channelUsers[a]);
					remoteUsers.push_back(temp);
				}
				
				//If Callsign is set, send it to other users
				if(localUser.getCallsign() != "")
					m_api.sendData(connection,getUserIDs(),localUser.getUdpMsg(NTFY_USR,0),localUser.getUdpId(NTFY_USR,0).c_str());
				//If Location is set, send it to other users
				if(localUser.getLocation().getLon() != 0.000)
					m_api.sendData(connection,getUserIDs(),localUser.getUdpMsg(NTFY_LOC,0),localUser.getUdpId(NTFY_LOC,0).c_str());
				
				//If Radios are initialized, send data to other users
				for(int a = 0; a < localUser.radioCount(); a++) {
					if(localUser.getRadio(a).getDialedFrequency() != "")
						m_api.sendData(connection,getUserIDs(),localUser.getUdpMsg(NTFY_COM,a),localUser.getUdpId(NTFY_COM,a).c_str());
				}
				
				//And finally send a data request
				m_api.sendData(connection,getUserIDs(),localUser.getUdpMsg(NTFY_ASK,0),localUser.getUdpId(NTFY_ASK,0).c_str());
				
				fgcom_prevTransmissionMode = m_api.getLocalUserTransmissionMode();
				m_api.requestLocalUserTransmissionMode(TM_PUSH_TO_TALK);
				m_api.log("Enabled push-to-talk");
			}
			else {
				//Add user to identitys
				fgcom_identity temp;
				temp.setUid(userID);
				remoteUsers.push_back(temp);
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
	
	struct sockaddr_in servaddr, cliaddr;
	unsigned int recv_len,slen= sizeof(cliaddr);
	int fgcom_UDPServer_sockfd, i = -1;
	char buf[BUFLEN];
	
	
	//create a UDP socket
	if ((fgcom_UDPServer_sockfd =socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		pluginLog("Create Socket Failed!");
		return;
	}
	
	// zero out the structure
	memset((char *) &servaddr, 0, sizeof(servaddr));
	
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
 
	// Bind the socket with the server address
    bool bind_ok = false;
    int fgcom_udp_port_used;
    for (fgcom_udp_port_used = PORT; fgcom_udp_port_used < PORT + 10; fgcom_udp_port_used++) {
        servaddr.sin_port = htons(fgcom_udp_port_used); 
        if ( bind(fgcom_UDPServer_sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) >= 0 ) { 
            pluginLog("[UDP-server] udp socket bind succeeded");
            bind_ok = true;
            break;
        }
    }
    if (!bind_ok) {
        pluginLog("[UDP-server] udp socket bind to port failed");
        exit(EXIT_FAILURE); 
    }
	
	std::string preData, curBuffer;
	std::vector<std::string> splitBuffer, finalBuffer;
	fgcom_keyvalue udpData;
	unsigned int c = 0;
	fgcom_radio radioBuffer;
	fgcom_location locBuffer;
	fgcom_identity prevState;

	m_api.log(std::string("UDP server up and waiting for data at "+std::to_string(servaddr.sin_addr.s_addr)+":"+std::to_string(fgcom_udp_port_used)).c_str());
	
	const std::chrono::milliseconds notifyPingInterval = std::chrono::milliseconds(NOTIFYPINGINTERVAL);
	auto lastPing = std::chrono::system_clock::now();
	
	while(udpServerRunning) {
		//Ping
		if (std::chrono::system_clock::now() > lastPing + notifyPingInterval) {
			m_api.sendData(m_api.getActiveServerConnection(),getUserIDs(),localUser.getUdpMsg(NTFY_PNG,0),localUser.getUdpId(NTFY_PNG,0).c_str());
			lastPing = std::chrono::system_clock::now();
		}
		//receive data, this is a blocking call
		recv_len = recvfrom(fgcom_UDPServer_sockfd, buf, BUFLEN, 0, (struct sockaddr *) &cliaddr, &slen);
		curBuffer = buf;
		//If nothing changed lets just skip parsing
		if(preData == curBuffer)
			continue;

		//std::cout<<"Received packet from "<<inet_ntoa(cliaddr.sin_addr)<<":"<<ntohs(cliaddr.sin_port)<<std::endl;
		pluginDbg(curBuffer);
		udpData.clear();
		
		///@todo Add check to make sure message was valid		
		splitBuffer = udpData.splitStrings(curBuffer,",");
		
		//pluginDbg(splitBuffer[0]);
		
		for(c = 0; c < splitBuffer.size(); c++) {
			///@todo Add check to make sure message was valid
			finalBuffer = udpData.splitStrings(splitBuffer[c],"=");
			if(finalBuffer.size() == 2)
				udpData.add(finalBuffer[0], finalBuffer[1]);
		}
					
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
				
				localUser.setRadio(radio, r - 1);
			}
			else
				break;
			r++;
		}
		
	
		//See if we need to send any data
		if(localUser.getCallsign() != prevState.getCallsign()) {
			m_api.sendData(m_api.getActiveServerConnection(),getUserIDs(),localUser.getUdpMsg(NTFY_USR,0),localUser.getUdpId(NTFY_USR,0).c_str());
		}
		
		//Check Location
		if(!localUser.getLocation().isEqual(prevState.getLocation())) {
			m_api.sendData(m_api.getActiveServerConnection(),getUserIDs(),localUser.getUdpMsg(NTFY_LOC,0),localUser.getUdpId(NTFY_LOC,0).c_str());
		}
		
		
		//Check radio PTT
		int a = 0;
		for(a = 0; a < localUser.radioCount(); a++) {
			if(localUser.getRadio(a).isPTT() != prevState.getRadio(a).isPTT()) {
				if(localUser.getRadio(a).isPTT()) {
					m_api.requestMicrophoneActivationOvewrite(true);					
					m_api.sendData(m_api.getActiveServerConnection(),getUserIDs(),localUser.getUdpMsg(NTFY_COM,a),localUser.getUdpId(NTFY_COM,a).c_str());

				}
				else {
					m_api.requestMicrophoneActivationOvewrite(false);
					m_api.sendData(m_api.getActiveServerConnection(),getUserIDs(),localUser.getUdpMsg(NTFY_COM,a),localUser.getUdpId(NTFY_COM,a).c_str());

				}
			}
		}
		
		prevState = localUser;
		preData = buf;
	}
	pluginDbg("Server loop done!");
	return;
}

bool FgcomPlugin::onReceiveData(mumble_connection_t connection, mumble_userid_t senderID, const uint8_t *data,
                                std::size_t dataLength, const char *dataID) noexcept {
	//convert data to string
	std::string msg;
	for(int a = 0; a < dataLength; a++)
		msg.push_back(data[a]);
	
	pluginDbg("Receved "+msg+" From: " + std::to_string(senderID));
	pluginDbg(dataID);			
}

std::vector<mumble_userid_t> FgcomPlugin::getUserIDs() {
	std::vector<mumble_userid_t> IDs;
	for(unsigned int a = 0; a < remoteUsers.size();a++) {
		IDs.push_back(remoteUsers[a].getUid());
	}
	return IDs;
}
