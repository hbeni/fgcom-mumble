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
 *
 * Mumble API:
 * Copyright 2019-2020 The Mumble Developers. All rights reserved.
 * Use of this source code is governed by a BSD-style license
 * that can be found in the LICENSE file at the root of the
 * Mumble source tree or at <https://www.mumble.info/LICENSE>.
 */

// Include the definitions of the plugin functions
// Note that this will also include PluginComponents.h
#include "globalVars.h"
#include "MumblePlugin.h"
#include "MumbleAPI.h"
#include "fgcom-mumble.h"
#include "plugin_io.h"
#include "radio_model.h"
#include "audio.h"

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <cstring>
#include <vector>
#include <string>
#include <thread>

#ifdef DEBUG
// include debug code
#include "debug.cpp"
#endif


// Mubmle API global vars.
MumbleAPI mumAPI;
mumble_connection_t activeConnection;
plugin_id_t ownPluginID;

// Plugin Version
#define FGCOM_VERSION_MAJOR 0
#define FGCOM_VERSION_MINOR 1
#define FGCOM_VERSION_PATCH 0


// Global plugin state
int  fgcom_specialChannelID = -1;
bool fgcom_inSpecialChannel = false; // adjust using fgcom_setPluginActive()!


/*******************
 * Some helpers    *
 ******************/

// Stream overload for version printing
std::ostream& operator<<(std::ostream& stream, const version_t version) {
	stream << "v" << version.major << "." << version.minor << "." << version.patch;
	return stream;
}


/*
 * Activate the plugin handling
 * 
 * @param bool active if the plugin handling stuff should be active
 */
transmission_mode_t fgcom_prevTransmissionMode = TM_VOICE_ACTIVATION; // we use voice act as default in case something goes wrong
void fgcom_setPluginActive(bool active) {
    mumble_error_t merr;
    fgcom_inSpecialChannel = active;
    if (active) {
        pluginLog("plugin handling activated: ");
        mumAPI.log(ownPluginID, "plugin handling activated");
        
        // switch to push-to-talk
        merr = mumAPI.getLocalUserTransmissionMode(ownPluginID, &fgcom_prevTransmissionMode);
        if (merr == STATUS_OK) {
            merr = mumAPI.requestLocalUserTransmissionMode(ownPluginID, TM_PUSH_TO_TALK);
            mumAPI.log(ownPluginID, "enabled push-to-talk");
        }
        
    } else {
        pluginLog("plugin handling deactivated");
        mumAPI.log(ownPluginID, "plugin handling deactivated");
        
        // restore old transmission mode
        merr = mumAPI.requestLocalUserTransmissionMode(ownPluginID, fgcom_prevTransmissionMode);
    }
    
}
bool fgcom_isPluginActive() {
    return fgcom_inSpecialChannel;
}

/*
 * See if the radio is operable
 * 
 * @param fgcom_radio the radio to check
 * @return bool true, wehn it is
 */
bool fgcom_radio_isOperable(fgcom_radio r) {
    //pluginDbg("fgcom_radio_operable() called");
    //pluginDbg("fgcom_radio_operable()    r.frequency="+r.frequency);
    //pluginDbg("fgcom_radio_operable()    r.power_btn="+std::to_string(r.power_btn));
    //pluginDbg("fgcom_radio_operable()    r.volts="+std::to_string(r.volts));
    //pluginDbg("fgcom_radio_operable()    r.serviceable="+std::to_string(r.serviceable));

    bool radio_serviceable = r.serviceable;
    bool radio_switchedOn  = r.power_btn;
    bool radio_powered     = (r.volts >= 1.0)? true:false; // some aircraft report boolean here, so treat 1.0 as powered
    
    bool operable = (radio_serviceable && radio_switchedOn && radio_powered);
    //pluginDbg("fgcom_radio_operable() result: operable="+std::to_string(operable));
    return operable;
}

/*
 * Handle PTT change of local user
 * 
 * This will check the local radio state and activate the mic if all is operable.
 * When no PTT or no radio is operable, mic is closed.
 */
void fgcom_handlePTT() {
    if (fgcom_isPluginActive()) {
        pluginDbg("Handling PTT state");
        // see which radio was used and if its operational.
        bool radio_serviceable, radio_powered, radio_switchedOn, radio_ptt;
        bool radio_ptt_result = false; // if we should open or close the mic, default no
        if (fgcom_local_client.radios.size() > 0) {
            for (int i=0; i<fgcom_local_client.radios.size(); i++) {
                radio_ptt         = fgcom_local_client.radios[i].ptt;
                
                if (radio_ptt) {
                    //if (radio_serviceable && radio_switchedOn && radio_powered) {
                    if ( fgcom_radio_isOperable(fgcom_local_client.radios[i])) {
                        pluginDbg("  COM"+std::to_string(i+1)+" PTT active and radio is operable -> open mic");
                        radio_ptt_result = true;
                        break; // we only have one output stream, so further search makes no sense
                    } else {
                        pluginLog("  COM"+std::to_string(i+1)+" PTT active but radio not operable!");
                    }
                } else {
                    pluginDbg("  COM"+std::to_string(i+1)+" PTT off");
                }
            }
        }
        
        if (radio_ptt_result) pluginDbg("final PTT/radio openmic state: "+std::to_string(radio_ptt_result));
        mumAPI.requestMicrophoneActivationOvewrite(ownPluginID, radio_ptt_result);
        
    } else {
        // Todo: do we need to reset something or so? i think no:
        //       plugin deactivation will already handle setting the old transmission mode,
        //       so the mic will be open according to that...
        mumAPI.requestMicrophoneActivationOvewrite(ownPluginID, false);
        pluginDbg("Handling PTT state: PLUGIN NOT ACTIVE");
    }
}


/*
 * To be called when plugin is initialized to set up
 * local stuff. the function gets called from
 *  - mumble_init()                  (plugin is loaded but not neccesarily connected to server)
 *  - mumble_onServerSynchronized()  (we are connected but plugin is not neccesarily loaded)
 *  - mumble_onServerConnected       (we are connected but plugin is not neccesarily loaded)
 */
bool fgcom_offlineInitDone = false;
bool fgcom_onlineInitDone = false;
std::thread::id udpServerThread_id;
mumble_error_t fgcom_initPlugin() {
    if (! fgcom_offlineInitDone && ! fgcom_onlineInitDone) mumAPI.log(ownPluginID, "Plugin initializing");
    
    /*
     * OFFLINE INIT: Here init stuff that can be initialized offline.
     * Do this just once.
     */     
    if (! fgcom_offlineInitDone) {
        pluginLog("performing offline initialization");
        
        #ifdef DEBUG
        // In Debug mode, start a detached thread that puts internal state to stdout every second
        std::thread debug_out_thread(debug_out_internal_state);
        debug_out_thread.detach();
        #endif
        
        // start the local udp server.
        pluginDbg("starting local UDP server");
        std::thread udpServerThread(fgcom_spawnUDPServer);
        udpServerThread_id = udpServerThread.get_id();
        udpServerThread.detach();
        //std::cout << "FGCOM: udp server started; id=" << udpServerThread_id << std::endl;
        pluginDbg("udp server started");
        
        fgcom_offlineInitDone = true;
    }
    
    
    /*
     * ONLINE INIT: Here do things that afford an established connection to the server
     */
    if (fgcom_isConnectedToServer()) {
        if (! fgcom_onlineInitDone) {
            pluginLog("performing online initialization");
            
            // fetch local user id from server, but only if we are already connected
            mumble_userid_t localUser;
            if (mumAPI.getLocalUserID(ownPluginID, activeConnection, &localUser) != STATUS_OK) {
                pluginLog("Failed to retrieve local user ID");
                return EC_USER_NOT_FOUND; // abort online init - something horribly went wrong.
            } else {
                fgcom_local_client.mumid = localUser; // store id to localUser
                pluginLog("got local clientID="+std::to_string(localUser));
                mumAPI.freeMemory(ownPluginID, &localUser);
            }
            
            
            // fetch all channels from server in order to get the special fgcom-mumble channel ID
            //fgcom_specialChannelID
            size_t channelCount;
            mumble_channelid_t *channels;
            if (mumAPI.getAllChannels(ownPluginID, activeConnection, &channels, &channelCount) != STATUS_OK) {
                pluginLog("Failed to retrieve all channel IDs");
                return EC_CHANNEL_NOT_FOUND; // abort online init - something horribly went wrong.
            } else {
                pluginLog("Server has "+std::to_string(channelCount)+" channels:");
                for (size_t ci=0; ci<channelCount; ci++) {
                    pluginDbg("  resolving channel name for id="+std::to_string(channels[ci]));
                    char *channelName;
                    mumble_error_t cfres = mumAPI.getChannelName(ownPluginID, activeConnection, channels[ci], &channelName);
                    if (cfres == STATUS_OK) {
                        pluginDbg("  channelID="+std::to_string(channels[ci])+" '"+channelName+"'");
                        if (strcmp("fgcom-mumble", channelName) == 0) {
                            fgcom_specialChannelID = channels[ci];
                            pluginDbg("    special channel id found! id="+std::to_string(fgcom_specialChannelID));
                            break;
                        }
                        mumAPI.freeMemory(ownPluginID, channelName);
                    } else {
                        pluginDbg("Error fetching channel names: rc="+std::to_string(cfres));
                        return EC_CHANNEL_NOT_FOUND; // abort online init - something horribly went wrong.
                    }
                }
                
                if (fgcom_specialChannelID == -1) {
                    pluginLog("ERROR: FAILED TO RETRIEVE 'fgcom-mumble' CHANNEL! Please setup such an channel.");
                    mumAPI.log(ownPluginID, std::string("Failed to retrieve 'fgcom-mumble' special channel! Please setup such an channel.").c_str());
                }
            }
            mumAPI.freeMemory(ownPluginID, channels);
            
            
            // In case we are already in the special channel, broadcast our state.
            // This is especially for the case when we did connect and join the channel without
            // active plugin and are activating it now.
            pluginDbg("Check if we are already in the special channel and thus need to activate");
            mumble_channelid_t localChannelID;
            mumble_error_t glcres = mumAPI.getChannelOfUser(ownPluginID, activeConnection, fgcom_local_client.mumid, &localChannelID);
            if (glcres == STATUS_OK) {
                if (fgcom_specialChannelID == localChannelID) {
                    pluginDbg("Already in special channel at init time");
                    fgcom_setPluginActive(true);
                    notifyRemotes(0); // send our state to all clients
                    notifyRemotes(3); // request all other state
                } else {
                    pluginDbg("Channels not equal: special="+std::to_string(fgcom_specialChannelID)+" == cur="+std::to_string(localChannelID));
                }
            } else {
                pluginLog("Error fetching current active channel: rc="+std::to_string(glcres));
                return EC_CHANNEL_NOT_FOUND; // abort online init - something horribly went wrong.
            }
            mumAPI.freeMemory(ownPluginID, &localChannelID);
            
            if (!fgcom_isPluginActive()) fgcom_setPluginActive(fgcom_isPluginActive()); // print some nice message to start
            
            // ... more needed?
            
            
            fgcom_onlineInitDone = true;
            
        }
        
    } else {
        pluginLog("fgcom_initPlugin(): not connected, so no online init possible (will try later)");
        return STATUS_OK; // OK - we will try later
    }
    
    
    // Plugin init complete
    return STATUS_OK;
}


//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////// PLUGIN IMPLEMENTATION ///////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////


// Notiz: Loggen im mumble-Fenster: mumAPI.log(ownPluginID, "Received API functions");
// Notiz: Loggen ins terminal-log:  pluginLog("Registered Mumble's API functions");

/*  INIT Sequence
    Call mumble_setMumbleInfo (if implemented)
    Call mumble_getAPIVersion to get the required API version (respected in the next call)
    Call mumble_registerAPIFunctions
    Call mumble_init
*/


//////////////////////////////////////////////////////////////
//////////////////// OBLIGATORY FUNCTIONS ////////////////////
//////////////////////////////////////////////////////////////
// All of the following function must be implemented in order for Mumble to load the plugin
mumble_error_t mumble_init(uint32_t id) {
    pLog() << "Registered PluginID: " << id << std::endl;
	ownPluginID = id;
    
    // perform initialization if not done already (or missing parts of it;
    // this is called when loading the plugin which may be done offline)
    mumble_error_t init_rc = fgcom_initPlugin();
    if (STATUS_OK != init_rc) return init_rc;
	pluginLog("Initialized plugin");


	// STATUS_OK is a macro set to the appropriate status flag (ErrorCode)
	// If you need to return any other status have a look at the ErrorCode enum
	// inside PluginComponents.h and use one of its values
	return STATUS_OK;
}

void mumble_shutdown() {
	pluginLog("Shutdown plugin");

    // Let the UDP server shutdown itself
    fgcom_shutdownUDPServer();
    
    fgcom_setPluginActive(false); // stop plugin handling
    
	mumAPI.log(ownPluginID, "Plugin deactivated");
}

const char* mumble_getName() {
	// The pointer returned by this functions has to remain valid forever and it must be able to return
	// one even if the plugin hasn't loaded (yet). Thus it may not require any variables that are only set
	// once the plugin is initialized
	// For most cases returning a hard-coded String-literal should be what you aim for
	return "FGCom";
}

version_t mumble_getAPIVersion() {
	// MUMBLE_PLUGIN_API_VERSION will always contain the API version of the used header file (the one used to build
	// this plugin against). Thus you should always return that here in order to no have to worry about it.
	return MUMBLE_PLUGIN_API_VERSION;
}

void mumble_registerAPIFunctions(MumbleAPI api) {
	// In this function the plugin is presented with a struct of function pointers that can be used
	// to interact with Mumble. Thus you should store it somewhere safe for later usage.
    // This is called on plugin loading time, where we might not be connected.
	mumAPI = api;

	pluginLog("Registered Mumble's API functions");
}


//////////////////////////////////////////////////////////////
///////////////////// OPTIONAL FUNCTIONS /////////////////////
//////////////////////////////////////////////////////////////
// The implementation of below functions is optional. If you don't need them, don't include them in your
// plugin

void mumble_setMumbleInfo(version_t mumbleVersion, version_t mumbleAPIVersion, version_t minimalExpectedAPIVersion) {
	// this function will always be the first one to be called. Even before init()
	// In here you can get info about the Mumble version this plugin is about to run in.
	pLog() << "Mumble version: " << mumbleVersion << "; Mumble API-Version: " << mumbleAPIVersion << "; Minimal expected API-Version: "
		<< minimalExpectedAPIVersion << std::endl;
}

version_t mumble_getVersion() {
	// Mumble uses semantic versioning (see https://semver.org/)
	// { major, minor, patch }
	return { FGCOM_VERSION_MAJOR, FGCOM_VERSION_MINOR, FGCOM_VERSION_PATCH };
}

const char* mumble_getAuthor() {
	// For the returned pointer the same rules as for getName() apply
	// In short: in the vast majority of cases you'll want to return a hard-coded String-literal
	return "Benedikt Hallinger";
}

const char* mumble_getDescription() {
	// For the returned pointer the same rules as for getName() apply
	// In short: in the vast majority of cases you'll want to return a hard-coded String-literal
	return "FGCOM provides an aircraft radio simulation.";
}

uint32_t mumble_getFeatures() {
	// Tells Mumble whether this plugin delivers some known common functionality. See the PluginFeature enum in
	// PluginComponents.h for what is available.
	// If you want your plugin to deliver positional data, you'll want to return FEATURE_POSITIONAL
	//return FEATURE_NONE;
    return FEATURE_AUDIO;
}

uint32_t mumble_deactivateFeatures(uint32_t features) {
	pLog() << "Asked to deactivate feature set " << features << std::endl;

	// All features that can't be deactivated should be returned
	return features;
}


void mumble_onServerConnected(mumble_connection_t connection) {
    pLog() << "Established server-connection with ID " << connection << std::endl;
    
    // perform initialization if not done already (or missing parts of it;
    // particularly it will run the online part if the plugin was loaded when
    // we were not connected yet)
    activeConnection = connection;
    fgcom_initPlugin();    
    
}

void mumble_onServerDisconnected(mumble_connection_t connection) {
    pLog() << "Disconnected from server-connection with ID " << connection << std::endl;
    
    fgcom_setPluginActive(false);
    activeConnection = -1;
}

void mumble_onServerSynchronized(mumble_connection_t connection) {
	// The client has finished synchronizing with the server. Thus we can now obtain a list of all users on this server
    // This is only called if the module was loaded during connecting time.
    // Sync status can be tested with isConnectionSynchronized()
	pLog() << "Server has finished synchronizing (ServerConnection: " << connection << ")" << std::endl ;

	size_t userCount;
	mumble_userid_t *userIDs;

	if (mumAPI.getAllUsers(ownPluginID, activeConnection, &userIDs, &userCount) != STATUS_OK) {
		pluginLog("[ERROR]: Can't obtain user list");
		return;
	}

	pLog() << "There are " << userCount << " users on this server. Their names are:" << std::endl;

	for(size_t i=0; i<userCount; i++) {
		char *userName;
		mumAPI.getUserName(ownPluginID, connection, userIDs[i], &userName);
		
		pLog() << "\t" << userName << std::endl;

		mumAPI.freeMemory(ownPluginID, userName);
	}

	mumAPI.freeMemory(ownPluginID, userIDs);


    // perform initialization if not done already (or missing parts of it;
    // particularly it will run the online part if the plugin was loaded when
    // we were not connected/synchronized yet)
    fgcom_initPlugin();
}

void mumble_onChannelEntered(mumble_connection_t connection, mumble_userid_t userID, mumble_channelid_t previousChannelID, mumble_channelid_t newChannelID) {
    // Called for each user entering the channel. When newly entering the channel ourself, this gets called for every user.
    
	std::ostream& stream = pLog() << "User with ID " << userID << " entered channel with ID " << newChannelID << ".";

	// negative ID means that there was no previous channel (e.g. because the user just connected)
	if (previousChannelID >= 0) {
		stream << " He came from channel with ID " << previousChannelID << ".";
	}
	stream << " (ServerConnection: " << connection << ")" << std::endl;

    
    if (userID == fgcom_local_client.mumid) {
        stream << " OH! thats me! hello myself!";
        if (newChannelID == fgcom_specialChannelID) {
            pluginDbg("joined special channel, activating plugin functions");
            fgcom_setPluginActive(true);
            notifyRemotes(0); // send our state to all users
        }
    } else {
        if (fgcom_isPluginActive()) {
            // if we are in the special channel, update new clinets with our state
            pluginDbg("send state to freshly joined user");
            notifyRemotes(0, -1, userID);
        }
    }

}

void mumble_onChannelExited(mumble_connection_t connection, mumble_userid_t userID, mumble_channelid_t channelID) {
	pLog() << "User with ID " << userID << " has left channel with ID " << channelID << ". (ServerConnection: " << connection << ")" << std::endl;
    
    //pluginDbg("userid="+std::to_string(userID)+"  mumid="+std::to_string(fgcom_local_client.mumid)+"  pluginActive="+std::to_string(fgcom_isPluginActive()));
    if (userID == fgcom_local_client.mumid && fgcom_isPluginActive()) {
        pluginDbg("left special channel, deactivating plugin functions");
        fgcom_setPluginActive(false);
    }
    
}

void mumble_onUserTalkingStateChanged(mumble_connection_t connection, mumble_userid_t userID, talking_state_t talkingState) {
	std::ostream& stream = pLog() << "User with ID " << userID << " changed his talking state to ";

	// The possible values are contained in the TalkingState enum inside PluginComponent.h
	switch(talkingState) {
		case INVALID:
			stream << "Invalid";
			break;
		case PASSIVE:
			stream << "Passive";
			break;
		case TALKING:
			stream << "Talking";
			break;
		case WHISPERING:
			stream << "Whispering";
			break;
		case SHOUTING:
			stream << "Shouting";
			break;
		default:
			stream << "Unknown (" << talkingState << ")";
	}

	stream << ". (ServerConnection: " << connection << ")" << std::endl;
    
}

// Note: Audio input is only possible with open mic. fgcom_hanldePTT() takes care of that.
bool mumble_onAudioInput(short *inputPCM, uint32_t sampleCount, uint16_t channelCount, bool isSpeech) {
	//pLog() << "Audio input with " << channelCount << " channels and " << sampleCount << " samples per channel encountered. IsSpeech: "
	//	<< isSpeech << std::endl;
    /*pluginDbg("  plugin active="+std::to_string(fgcom_isPluginActive()));
    if (fgcom_isPluginActive()) {
        // see which radio was used and if its operational. If not, null out the stream
        //bool activate = true;
        requestMicrophoneActivationOvewrite(ownPluginID, activate);
    }*/
    
    // Recheck that mic is open; close it immediately when radio fails.
    fgcom_handlePTT();
    
	// mark inputPCM as unused
	(void) inputPCM;

	// This function returns whether it has modified the audio stream
	return false;
}

bool mumble_onAudioSourceFetched(float *outputPCM, uint32_t sampleCount, uint16_t channelCount, bool isSpeech, mumble_userid_t userID) {
	//std::ostream& stream = pLog() << "Audio output source with " << channelCount << " channels and " << sampleCount << " samples per channel fetched.";
    // the PCM format is an float array. The cells are inidvidual apmplitudes.
    // With two channels, the first float at outputPCM[0] the left channel, outputPCM[1] right, [2] left etc.
    //  channelCount The amount of channels in the audio
    //  sampleCount The amount of sample points per channel
    // for two channels at 3 samples we get the following array:
    //   [0]    left channel, first sample
    //   [1]    right channel, first sample
    //   [2]    left channel, second sample
    //   [3]    right channel, second sample
    //   [4]    left channel, third sample
    //   [5]    right channel, third sample
    //
    // loop over every channels samples
    /*for (uint32_t c=0; c<channelCount; c++) {
        for (uint32_t s=c; s<channelCount*sampleCount; s+=channelCount) {
            std::cout << "["<< c << "]s="<< s <<" ";
            if (c==1) outputPCM[s] = 0; // mute left channel
        }
    }*/
  
    
    // See if the plugin is activated and if the audio source is speech.
    // We let the audio trough in case plugin is not active.
    pluginDbg("mumble_onAudioSourceFetched(): plugin active="+std::to_string(fgcom_isPluginActive()));
    bool rv = false;  // return value; false means the stream was not touched
    if (fgcom_isPluginActive() && isSpeech) {
        // This means, that the remote client was able to send, ie. his radio had power to transmit (or its a pluginless mumble client).
        pluginDbg("mumble_onAudioSourceFetched():   plugin active+speech detected from id="+std::to_string(userID));
        
        float bestSignalStrength = -1.0; // we want to get the connections signal strength.
        fgcom_radio matchedLocalRadio;
        bool isLandline = false;
        
        // Fetch the remote clients data
        auto search = fgcom_remote_clients.find(userID);
        if (search != fgcom_remote_clients.end()) {
            // we found remote state.
            fgcom_client rmt = fgcom_remote_clients[userID];
            pluginDbg("mumble_onAudioSourceFetched():   sender callsign="+rmt.callsign);
            
            // lets search the used radio(s) and determine best signal strength.
            // currently mumble has only one voice stream per client, so we assume it comes from the best matching radio.
            // Note: If we are PTTing ourself currently, the radio cannot receive at the moment (half-duplex mode!)
            pluginDbg("mumble_onAudioSourceFetched():   sender registered rmt-radios: "+std::to_string(rmt.radios.size()));
            for (int ri=0; ri<rmt.radios.size(); ri++) {
                pluginDbg("mumble_onAudioSourceFetched():   check remote radio #"+std::to_string(ri));
                pluginDbg("mumble_onAudioSourceFetched():    frequency='"+rmt.radios[ri].frequency+"'");
                pluginDbg("mumble_onAudioSourceFetched():    ptt='"+std::to_string(rmt.radios[ri].ptt)+"'");
                pluginDbg("mumble_onAudioSourceFetched():    txpwr='"+std::to_string(rmt.radios[ri].pwr)+"'");
                if (rmt.radios[ri].ptt) {
                    pluginDbg("mumble_onAudioSourceFetched():     PTT detected");
                    // The remote radio does transmit currently.
                    // See if we have an operable radio tuned to that frequency
                    fgcom_client lcl = fgcom_local_client;
                    bool frequencyIsListenedTo = false;
                    pluginDbg("mumble_onAudioSourceFetched():     check local radios for frequency match");
                    for (int lri=0; lri<lcl.radios.size(); lri++) {
                        pluginDbg("mumble_onAudioSourceFetched():     checking local radio #"+std::to_string(lri));
                        pluginDbg("mumble_onAudioSourceFetched():       frequency='"+lcl.radios[lri].frequency+"'");
                        pluginDbg("mumble_onAudioSourceFetched():       operable='"+std::to_string(fgcom_radio_isOperable(lcl.radios[lri]))+"'");
                        pluginDbg("mumble_onAudioSourceFetched():       ptt='"+std::to_string(lcl.radios[lri].ptt)+"'");
                        
                        // detect landline/intercom
                        if (lcl.radios[lri].frequency.substr(0, 5) == "PHONE"
                            && lcl.radios[lri].frequency == rmt.radios[ri].frequency 
                            && fgcom_radio_isOperable(lcl.radios[lri])) {
                            pluginDbg("mumble_onAudioSourceFetched():       local_radio="+std::to_string(lri)+"  PHONE mode detected");
                            // Best quality, full-duplex mode
                            matchedLocalRadio = lcl.radios[lri];
                            bestSignalStrength = 1.0;
                            isLandline = true;
                        
                        // normal radio operation
                        } else if (lcl.radios[lri].frequency == rmt.radios[ri].frequency
                            && fgcom_radio_isOperable(lcl.radios[lri])
                            && !lcl.radios[lri].ptt) {
                            pluginDbg("mumble_onAudioSourceFetched():       local_radio="+std::to_string(lri)+"  frequency "+lcl.radios[lri].frequency+" matches!");
                            // we are listening on that frequency!
                            // determine signal strenght for this connection
                            float ss = fgcom_radiowave_getSignalStrength(
                                lcl.lat, lcl.lon, lcl.alt,
                                rmt.lat, rmt.lon, rmt.alt,
                                rmt.radios[ri].pwr);
                            pluginDbg("mumble_onAudioSourceFetched():       signalStrength="+std::to_string(ss));
                            if (ss > lcl.radios[lri].squelch && ss > bestSignalStrength) {
                                // the signal is stronger than our squelch and tops the current last best signal
                                bestSignalStrength = ss;
                                matchedLocalRadio  = lcl.radios[lri];
                                pluginDbg("mumble_onAudioSourceFetched():         taking it, its better than the previous one");
                            } else {
                                pluginDbg("mumble_onAudioSourceFetched():         not taking it. squelch="+std::to_string(lcl.radios[lri].squelch)+", previousBestSignal="+std::to_string(bestSignalStrength));
                            }
                        } else {
                            pluginDbg("mumble_onAudioSourceFetched():     nomatch");
                        }
                    }
                } else {
                    // the inspected remote radio did not PTT
                    pluginDbg("mumble_onAudioSourceFetched():     remote PTT OFF");
                }
            }
            
        } else {
            // we have no idea about the remote yet: treat him as if hes not in range
            // (this may especially happen with sending clients without enabled plugin!)
            pluginDbg("mumble_onAudioSourceFetched():   sender with id="+std::to_string(userID)+" not found in remote state. muting stream.");
            bestSignalStrength = 0.0;
        }
        
        
        // Now we got the connections signal strength.
        // It is either positive, or zero in case:
        //   - we did not have any info on the client
        //   - the client was out of range
        //   - we did not tune the frequency (or radio was broken, or radio squelch cut off)
        rv = true; // we adjust the stream in any case
        if (isLandline) {
            // we got a landline connection!
            pluginDbg("mumble_onAudioSourceFetched():   connected (phone)");
            fgcom_audio_makeMono(outputPCM, sampleCount, channelCount);
            fgcom_audio_filter(bestSignalStrength, outputPCM, sampleCount, channelCount);
            fgcom_audio_applyVolume(matchedLocalRadio.volume, outputPCM, sampleCount, channelCount);
            
        } else if (bestSignalStrength > 0.0) { 
            // we got a connection!
            pluginDbg("mumble_onAudioSourceFetched():   connected, bestSignalStrength="+std::to_string(bestSignalStrength));
            fgcom_audio_makeMono(outputPCM, sampleCount, channelCount);
            fgcom_audio_filter(bestSignalStrength, outputPCM, sampleCount, channelCount);
            fgcom_audio_addNoise(bestSignalStrength, outputPCM, sampleCount, channelCount);
            fgcom_audio_applyVolume(matchedLocalRadio.volume, outputPCM, sampleCount, channelCount);
            
        } else {
            pluginDbg("mumble_onAudioSourceFetched():   no connection, bestSignalStrength="+std::to_string(bestSignalStrength));
            memset(outputPCM, 0x00, (sampleCount*channelCount)*sizeof(float) );
        }
        
        
    } else {
        // plugin not active OR no speech detected
        // do nothing, leave the stream alone
        rv = false;
    }
    
    
    // go home
    if (!rv) (void) outputPCM;  // Mark ouputPCM as unused
    return rv;   // This function returns whether it has modified the audio stream
}

/*  I think we don't need this and should implement stuff in the function above.
bool mumble_onAudioOutputAboutToPlay(float *outputPCM, uint32_t sampleCount, uint16_t channelCount) {
	//pLog() << "The resulting audio output has " << channelCount << " channels with " << sampleCount << " samples per channel" << std::endl;

	// mark outputPCM as unused
	(void) outputPCM;

	// This function returns whether it has modified the audio stream
	return false;
}*/

bool mumble_onReceiveData(mumble_connection_t connection, mumble_userid_t sender, const char *data, size_t dataLength, const char *dataID) {
	pLog() << "Received data with ID \"" << dataID << "\" from user with ID " << sender << ". Its length is " << dataLength
		<< ". (ServerConnection:" << connection << ")" << std::endl;

        if (dataLength > 0) {
            // if there is payload: handle it
            return handlePluginDataReceived(sender, std::string(dataID), std::string(data));
        }
        
        return false;
}

void mumble_onUserAdded(mumble_connection_t connection, mumble_userid_t userID) {
    /// Called when a new user gets added to the user model. This is the case when that new user freshly connects to the server the
	/// local user is on but also when the local user connects to a server other clients are already connected to (in this case this
	/// method will be called for every client already on that server).
	pLog() << "Added user with ID " << userID << " (ServerConnection: " << connection << ")" << std::endl;
}

void mumble_onUserRemoved(mumble_connection_t connection, mumble_userid_t userID) {
	pLog() << "Removed user with ID " << userID << " (ServerConnection: " << connection << ")" << std::endl;
}

void mumble_onChannelAdded(mumble_connection_t connection, mumble_channelid_t channelID) {
	pLog() << "Added channel with ID " << channelID << " (ServerConnection: " << connection << ")" << std::endl;
}

void mumble_onChannelRemoved(mumble_connection_t connection, mumble_channelid_t channelID) {
	pLog() << "Removed channel with ID " << channelID << " (ServerConnection: " << connection << ")" << std::endl;
}

void mumble_onChannelRenamed(mumble_connection_t connection, mumble_channelid_t channelID) {
	pLog() << "Renamed channel with ID " << channelID << " (ServerConnection: " << connection << ")" << std::endl;
}

void mumble_onKeyEvent(uint32_t keyCode, bool wasPress) {
	pLog() << "Encountered key " << (wasPress ? "press" : "release") << " of key with code " << keyCode << std::endl;
}

bool mumble_hasUpdate() {
	// This plugin never has an update
	return false;
}

bool mumble_getUpdateDownloadURL(char *buffer, uint16_t bufferSize, uint16_t offset) {
	/*static std::string url = "https://i.dont.exist/testplugin.zip";

	size_t writtenChars = url.copy(buffer, bufferSize, offset);

	if (writtenChars < bufferSize) {
		// URL has fit into the buffer -> append null byte and be done with it
		buffer[writtenChars] = '\0';
		return true;
	} else {
		std::cout << "Overflow" << std::endl;
		return false;
	}*/
    return false;
}
