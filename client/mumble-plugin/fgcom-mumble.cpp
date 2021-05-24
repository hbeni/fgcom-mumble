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
// Note that this will also include PluginComponents_v_1_0_x.h
#include "globalVars.h"
#include "mumble/MumblePlugin_v_1_0_x.h"
#include "mumble/MumbleAPI_v_1_0_x.h"
#include "fgcom-mumble.h"
#include "io_plugin.h"
#include "io_UDPServer.h"
#include "io_UDPClient.h"
#include "radio_model.h"
#include "audio.h"
#include "garbage_collector.h"

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <cstring>
#include <vector>
#include <map>
#include <string>
#include <thread>
#include <regex>
#include <fstream>
#include <memory>

#ifdef DEBUG
// include debug code
#include "debug.cpp"
#endif
#ifndef DEBUG
    bool fgcom_debugthread_running = false;
#endif




// Mubmle API global vars.
MumbleAPI_v_1_0_x mumAPI;
mumble_connection_t activeConnection;
mumble_plugin_id_t ownPluginID;

// Global plugin state
std::vector<mumble_channelid_t>  fgcom_specialChannelID;
bool fgcom_inSpecialChannel = false; // adjust using fgcom_setPluginActive()!

struct fgcom_config fgcom_cfg;


/*******************
 * Some helpers    *
 ******************/

// Stream overload for version printing
std::ostream& operator<<(std::ostream& stream, const mumble_version_t version) {
	stream << "v" << version.major << "." << version.minor << "." << version.patch;
	return stream;
}


/*
 * Activate the plugin handling
 * 
 * @param bool active if the plugin handling stuff should be active
 */
mumble_transmission_mode_t fgcom_prevTransmissionMode = TM_VOICE_ACTIVATION; // we use voice act as default in case something goes wrong
void fgcom_setPluginActive(bool active) {
    mumble_error_t merr;
    if (!fgcom_isConnectedToServer()) return; // not connected: do nothing.
    
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
        if (fgcom_inSpecialChannel) {
            pluginLog("plugin handling deactivated");
            mumAPI.log(ownPluginID, "plugin handling deactivated");
	
            // restore old transmission mode
            merr = mumAPI.requestLocalUserTransmissionMode(ownPluginID, fgcom_prevTransmissionMode);
        
            // disable PTT overwrite
            merr = mumAPI.requestMicrophoneActivationOvewrite(ownPluginID, false);
        }
        
    }
    
    fgcom_inSpecialChannel = active;
    fgcom_updateClientComment();
    
}
bool fgcom_isPluginActive() {
    return fgcom_inSpecialChannel;
}

/*
 * Handle UDP protocol PTT-Request change of local user
 *
 * This will check the local radio state and activate the mic if all is operable.
 * When no PTT or no radio is operable, mic is closed.
 *
 * Note: Opening the mic this way will trigger mumble_onUserTalkingStateChanged() which will
 * calculate the to-be-synced PTT state to remotes.
 */
void fgcom_handlePTT() {
    if (fgcom_isPluginActive()) {
        pluginDbg("Handling PTT protocol request state");
        // see which radio was used and if its operational.
        bool radio_serviceable, radio_powered, radio_switchedOn, radio_ptt;
        bool radio_ptt_result = false; // if we should open or close the mic, default no

        fgcom_localcfg_mtx.lock();
        for (const auto &lcl_idty : fgcom_local_client) {
            int iid          = lcl_idty.first;
            fgcom_client lcl = lcl_idty.second;
            if (lcl.radios.size() > 0) {
                for (int i=0; i<lcl.radios.size(); i++) {
                    radio_ptt = lcl.radios[i].ptt_req;
                    
                    if (radio_ptt) {
                        //if (radio_serviceable && radio_switchedOn && radio_powered) {
                        if ( lcl.radios[i].operable) {
                            pluginDbg("  COM"+std::to_string(i+1)+" PTT_REQ active and radio is operable -> open mic");
                            radio_ptt_result = true;
                            break; // we only have one output stream, so further search makes no sense
                        } else {
                            pluginLog("  COM"+std::to_string(i+1)+" PTT_REQ active but radio not operable!");
                        }
                    } else {
                        pluginDbg("  COM"+std::to_string(i+1)+" PTT_REQ off");
                    }
                }
            }
        }
        fgcom_localcfg_mtx.unlock();
        
        pluginDbg("final PTT/radio openmic state: "+std::to_string(radio_ptt_result));
        mumAPI.requestMicrophoneActivationOvewrite(ownPluginID, radio_ptt_result);
        
    } else {
        // Todo: do we need to reset something or so? i think no:
        //       plugin deactivation will already handle setting the old transmission mode,
        //       so the mic will be open according to that...
        pluginDbg("Handling PTT protocol request state: PLUGIN NOT ACTIVE");
    }
}

/*
 * Update mumble client comment
 */
std::string prevComment;  // so we can detect changes
void fgcom_updateClientComment() {
    
    if (fgcom_isConnectedToServer()) {
        std::string newComment;
        
        // fetch the present comment and read the part we don't want to manage
        std::string preservedComment;
        const char *comment;
        if (mumAPI.getUserComment(ownPluginID, activeConnection, localMumId, &comment) == STATUS_OK) {
            std::string comment_str(comment);
            std::smatch sm;
            std::regex re("^([\\w\\W]*)<p name=\"FGCOM\">.*");  // cool trick: . does not match newline, but \w with negated \W matches really everything
            //pluginDbg("fgcom_updateClientComment(): got previous comment: '"+comment_str+"'");
            if (std::regex_match(comment_str, sm, re)) {
                preservedComment = std::string(sm[1]);
                //pluginDbg("fgcom_updateClientComment(): extracted: '"+preservedComment+"'");
            } else {
                preservedComment = comment_str;
            }
        }
        mumAPI.freeMemory(ownPluginID, comment);

        // Add FGCom generic infos
        newComment += "<b>FGCom</b> (v"+std::to_string(FGCOM_VERSION_MAJOR)+"."+std::to_string(FGCOM_VERSION_MINOR)+"."+std::to_string(FGCOM_VERSION_PATCH)+"): ";
        newComment += (fgcom_isPluginActive())? "active" : "inactive";

        // Add Identity and frequency information
        fgcom_localcfg_mtx.lock();
        if (fgcom_local_client.size() > 0) {
            for (const auto &idty : fgcom_local_client) {
                int iid          = idty.first;
                fgcom_client lcl = idty.second;
                std::string frqs;
                if (lcl.radios.size() > 0) {
                    for (int i=0; i<lcl.radios.size(); i++) {
                        if (lcl.radios[i].frequency != "") {
                            if (i >= 1) frqs += ", ";
                            if (!lcl.radios[i].operable) frqs += "<i><font color=\"grey\">";
                            frqs += lcl.radios[i].dialedFRQ;
                            if (!lcl.radios[i].operable) frqs += "</font></i>";
                        }
                    }
                } else {
                    frqs = "-";
                }
                newComment += "<br/>&nbsp;&nbsp;<i>" + lcl.callsign + "</i>: " + frqs;
            }
        }   else {
            newComment += "<br/>&nbsp;&nbsp;<i>no callsigns registered</i>";
        }
        fgcom_localcfg_mtx.unlock();
        
        // Finally request to set the new comment
        // (this will broadcast the comment to other clients)
        if (prevComment != newComment) {
            std::string cmt = preservedComment + "<p name=\"FGCOM\">" + newComment;
            if (mumAPI.requestSetLocalUserComment(ownPluginID, activeConnection, cmt.c_str()) != STATUS_OK) {
                pluginLog("Failed at setting the local user's comment");
            } else {
                prevComment = newComment;
            }
        }
    }
}


/*
 * Load config file
 * This will parse the ini file and overwrite internal compile time defaults.
 * 
 * @return STATUS_OK on success, otherwise EC_GENERIC_ERROR 
 */
mumble_error_t fgcom_loadConfig() {
    std::vector<std::string> configFilePaths;
    std::string cfgName = "fgcom-mumble.ini";

    // Try to get config file from home dir
    char* pHomeDir;
#if defined(MINGW_WIN64) || defined(MINGW_WIN32)
    std::string dirSep = "\\";
    pHomeDir = getenv("USERPROFILE");
    if (pHomeDir) {
        configFilePaths.push_back(std::string(pHomeDir) + dirSep + cfgName);
	configFilePaths.push_back(std::string(pHomeDir) + dirSep + "Documents" + dirSep + cfgName);
    } else {
        pluginLog("[CFG] ERROR getting USERPROFILE from environment");
        // do not bail out: just use defaults. return EC_GENERIC_ERROR;
    }
#else
    std::string dirSep = "/";
    pHomeDir = getenv("HOME");
    if (pHomeDir) {
        configFilePaths.push_back(std::string(pHomeDir) + dirSep + "."+cfgName); // support "hidden dotfiles" in linux
        configFilePaths.push_back(std::string(pHomeDir) + dirSep + cfgName);
    } else {
        pluginLog("[CFG] ERROR getting HOME from environment");
        // do not bail out: just use defaults.  return EC_GENERIC_ERROR;
    }
#endif

    // Mumble plugin config
    // TODO: Once mumble offers some generic plugin config interface, we should integrate that here!
    //       -> try several locations, especially also the mumble plugin config dir (once that will be defined...)
    //       see also: https://github.com/mumble-voip/mumble/pull/3743#issuecomment-687560636


    // Try out to load the defined file locations.
    // We load them all in the order given, so the can overwrite each other. Ths may come in handy when
    // some distribution chooses to deliver adjusted defaults.
    for(std::string cfgFilePath : configFilePaths) {
        std::ifstream cfgFileStream(cfgFilePath);
        pluginDbg("[CFG] looking for plugin ini file at '"+cfgFilePath+"'");
        if (cfgFileStream.good()) {
            pluginLog("[CFG]   reading plugin ini file '"+cfgFilePath+"'");
            mumAPI.log(ownPluginID, std::string("reading ini file '"+cfgFilePath+"'").c_str());
            std::regex parse_key_value ("^([^;]\\w+?)\\s*=\\s*(.+?)(;.*)?\r?$");  // read ini style line, supporting spaces around the '=' and also linux/windows line endings
            std::string cfgLine;
            while (std::getline(cfgFileStream, cfgLine)) {
                std::smatch sm;
                if (std::regex_search(cfgLine, sm, parse_key_value)) {
                    // this is a valid token. Lets parse it!
                    std::string token_key   = sm[1];
                    std::string token_value = sm[2];
                    pluginDbg("[CFG] Parsing token: "+token_key+"="+token_value);

                    if (token_key == "radioAudioEffects") fgcom_cfg.radioAudioEffects = (token_value == "0" || token_value == "false" || token_value == "off" || token_value == "no")? false : true;
                    if (token_key == "allowHearingNonPluginUsers") fgcom_cfg.allowHearingNonPluginUsers = (token_value == "1" || token_value == "true" || token_value == "on" || token_value == "yes")? true : false;
                    if (token_key == "specialChannel")    fgcom_cfg.specialChannel    = token_value;
                    if (token_key == "udpServerHost")     fgcom_cfg.udpServerHost     = token_value;
                    if (token_key == "udpServerPort")     fgcom_cfg.udpServerPort     = std::stoi(token_value);
                    if (token_key == "logfile")           fgcom_cfg.logfile           = token_value;
                    
                    std::smatch sm_m;
                    std::regex re_mblmap ("^mapMumblePTT(\\d+)$");
                    if (std::regex_search(token_key, sm_m, re_mblmap)) {
                        int radio_id = std::stoi(sm_m[1]);
                        radio_id--; // convert to array index
                        fgcom_cfg.mapMumblePTT[radio_id] = (token_value == "1" || token_value == "true" || token_value == "on" || token_value == "yes")? true : false;
                    }
                }
            }
        } else {
            pluginLog("[CFG]   not using '"+cfgFilePath+"' (not existing or invalid format)");
        }
    }
    
    // Debug print final parsed config
    pluginDbg("[CFG] final parsed config:");
    pluginDbg("[CFG]   allowHearingNonPluginUsers="+std::to_string(fgcom_cfg.allowHearingNonPluginUsers));
    pluginDbg("[CFG]            radioAudioEffects="+std::to_string(fgcom_cfg.radioAudioEffects));
    pluginDbg("[CFG]               specialChannel="+fgcom_cfg.specialChannel);
    pluginDbg("[CFG]                udpServerHost="+fgcom_cfg.udpServerHost);
    pluginDbg("[CFG]                udpServerPort="+std::to_string(fgcom_cfg.udpServerPort));
    pluginDbg("[CFG]                      logfile="+fgcom_cfg.logfile);
    for (const auto& cv : fgcom_cfg.mapMumblePTT) {
        pluginDbg("[CFG]              mapMumblePTT["+std::to_string(cv.first)+"]="+std::to_string(cv.second));
    }
    
    return STATUS_OK;
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
bool fgcom_configDone = false;
std::thread::id udpServerThread_id;
std::thread::id gcThread_id;
mumble_userid_t localMumId;
mumble_error_t fgcom_initPlugin() {
    if (! fgcom_offlineInitDone && ! fgcom_onlineInitDone) {
        std::string debuginfo;
#ifdef DEBUG
        debuginfo = "(notice: this is a debug build)";
#endif
        mumAPI.log(ownPluginID, ("Plugin v"+std::to_string(FGCOM_VERSION_MAJOR)+"."+std::to_string(FGCOM_VERSION_MINOR)+"."+std::to_string(FGCOM_VERSION_PATCH)+" initializing "+debuginfo).c_str());
    }

    /*
     * Load config ini file, if present
     * The values given there will overwrite the defaults from the config struct.
     */
    if (! fgcom_configDone) {
        mumble_error_t configureResult = fgcom_loadConfig();
        if (configureResult != STATUS_OK) return configureResult;
        fgcom_configDone = true;
    }
    
    
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
        pluginDbg("udp server started");
        
        // start the local GC thread
        pluginDbg("starting garbage collector");
        std::thread gcThread(fgcom_spawnGarbageCollector);
        gcThread_id = gcThread.get_id();
        gcThread.detach();
        pluginDbg("garbage collector started");
        
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
                // update mumble session id to all known identities
                localMumId = localUser;
                fgcom_remotecfg_mtx.lock();
                for (const auto &idty : fgcom_local_client) {
                    fgcom_local_client[idty.first].mumid = localUser;
                }
                fgcom_remotecfg_mtx.unlock();
                pluginLog("got local clientID="+std::to_string(localUser));
            }
            
            
            // fetch all channels from server in order to get the special fgcom-mumble channel ID
            size_t channelCount;
            mumble_channelid_t *channels;
            if (mumAPI.getAllChannels(ownPluginID, activeConnection, &channels, &channelCount) != STATUS_OK) {
                pluginLog("Failed to retrieve all channel IDs");
                return EC_CHANNEL_NOT_FOUND; // abort online init - something horribly went wrong.
            } else {
                pluginLog("Server has "+std::to_string(channelCount)+" channels, looking for special ones");
                pluginDbg("  fgcom.specialChannel='"+fgcom_cfg.specialChannel+"'");
                for (size_t ci=0; ci<channelCount; ci++) {
                    pluginDbg("  resolving channel name for id="+std::to_string(channels[ci]));
                    const char *channelName;
                    mumble_error_t cfres = mumAPI.getChannelName(ownPluginID, activeConnection, channels[ci], &channelName);
                    if (cfres == STATUS_OK) {
                        pluginDbg("  channelID="+std::to_string(channels[ci])+" '"+channelName+"'");
                        std::string channelName_str(channelName);
                        if (std::regex_match(channelName_str, std::regex(fgcom_cfg.specialChannel, std::regex_constants::icase) )) {
                            fgcom_specialChannelID.push_back(channels[ci]);
                            pluginDbg("    special channel id found! name='"+channelName_str+"'; id="+std::to_string(channels[ci]));
                        }
                        mumAPI.freeMemory(ownPluginID, channelName);
                    } else {
                        pluginDbg("Error fetching channel names: rc="+std::to_string(cfres));
                        return EC_CHANNEL_NOT_FOUND; // abort online init - something horribly went wrong.
                    }
                }
                
                if (fgcom_specialChannelID.size() == 0) {
                    pluginLog("ERROR: FAILED TO RETRIEVE SPECIAL CHANNEL '"+fgcom_cfg.specialChannel+"'! Please setup such an channel.");
                    mumAPI.log(ownPluginID, std::string("Failed to retrieve special channel '"+fgcom_cfg.specialChannel+"'! Please setup such an channel.").c_str());
                }
            }
            mumAPI.freeMemory(ownPluginID, channels);
            
            
            // In case we are already in the special channel, synchronize state.
            // This is especially for the case when we did connect and join the channel without
            // active plugin and are activating it now.
            pluginDbg("Check if we are already in the special channel and thus need to activate");
            mumble_channelid_t localChannelID;
            mumble_error_t glcres = mumAPI.getChannelOfUser(ownPluginID, activeConnection, localMumId, &localChannelID);
            if (glcres == STATUS_OK) {
                if (std::find(fgcom_specialChannelID.begin(), fgcom_specialChannelID.end(), localChannelID) != fgcom_specialChannelID.end()) {
                    // Activate the plugin, and initialize synch (send state+ask for remote state)
                    pluginDbg("Already in special channel at init time: activating plugin.");
                    fgcom_setPluginActive(true);
                    notifyRemotes(0, NTFY_ALL); // send our state to all clients
                    notifyRemotes(0, NTFY_ASK); // request all other state
                } else {
                    pluginDbg("Not in special channel at init time: nothing to do.");
                }
            } else {
                pluginLog("Error fetching current active channel: rc="+std::to_string(glcres));
                return EC_CHANNEL_NOT_FOUND; // abort online init - something horribly went wrong.
            }
            
            if (!fgcom_isPluginActive()) fgcom_setPluginActive(fgcom_isPluginActive()); // print some nice message to start
            
            
            // Start to periodically send notifications (if needed)
            std::thread notifyThread(fgcom_notifyThread);
            notifyThread.detach();
            
            
            // Update client comment
            fgcom_updateClientComment();

            
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
    pluginLog("Registered PluginID: "+std::to_string(id));
	ownPluginID = id;
    
    // perform initialization if not done already (or missing parts of it;
    // this is called when loading the plugin which may be done offline)
    mumble_error_t init_rc = fgcom_initPlugin();
    if (STATUS_OK != init_rc) return init_rc;
	pluginLog("Initialized plugin");


	// STATUS_OK is a macro set to the appropriate status flag (ErrorCode)
	// If you need to return any other status have a look at the ErrorCode enum
	// inside PluginComponents_v_1_0_x.h and use one of its values
	return STATUS_OK;
}

void mumble_shutdown() {
	pluginLog("Shutdown plugin");

    pluginDbg("stopping threads");
    fgcom_shutdownUDPServer();
    fgcom_stopUDPClient();
    fgcom_shutdownGarbageCollector();
    
    fgcom_setPluginActive(false); // stop plugin handling
    
#ifdef DEBUG
    fgcom_debugthread_shutdown = true;
#endif

    // wait for all threads to have terminated
    pluginDbg("waiting for threads to finish");
    while (udpServerRunning || udpClientRunning || fgcom_gcThreadRunning || fgcom_debugthread_running) {
        // just wait for the servers to come down. This should not take long.
        // TODO: this may block forever. We probably should have some kind of timeout here.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // reenable a future init and reloading of config
    fgcom_offlineInitDone = false;
    fgcom_onlineInitDone  = false;
    fgcom_configDone      = false;
#ifdef DEBUG
    fgcom_debugthread_shutdown = false;
#endif
    
    pluginDbg("mumble_shutdown() complete.");
	mumAPI.log(ownPluginID, "Plugin deactivated");
}

MumbleStringWrapper mumble_getName() {
    static const char *name = "FGCom-mumble";

    MumbleStringWrapper wrapper;
    wrapper.data = name;
    wrapper.size = strlen(name);
    wrapper.needsReleasing = false;  // It's a static String and therefore doesn't need releasing

    return wrapper;
}

mumble_version_t mumble_getAPIVersion() {
	// MUMBLE_PLUGIN_API_VERSION will always contain the API version of the used header file (the one used to build
	// this plugin against). Thus you should always return that here in order to no have to worry about it.
	return MUMBLE_PLUGIN_API_VERSION;
}

void mumble_releaseResource(const void *pointer) {
    // currently a naive implementation just assuming char arrays to be cleaned that were established using 'new'.
    // (once we need to differentiate that more, we should maybe introduce some map/vector that gives us the information
    // which memory address to cast into the proper type?)
    delete [] (char*)pointer;  // to delete char arrays
}

void mumble_registerAPIFunctions(void *api) {
    // In this function the plugin is presented with a struct of function pointers that can be used
	// to interact with Mumble. Thus you should store it somewhere safe for later usage.

	// The pointer has to be cast to the respective API struct. You always have to cast to the same API version
	// as this plugin itself is using. Thus if this plugin is compiled using the API version 1.0.x (where x is an arbitrary version)
	// the pointer has to be cast to MumbleAPI_v_1_0_x.
	// Furthermore the struct HAS TO BE COPIED!!! Storing the pointer is not an option as it will become invalid quickly!

	// **If** you are using the same API version that is specified in the included header file (as you should), you
	// can simply use the MUMBLE_API_CAST to cast the pointer to the correct type and automatically dereferencing it.
	mumAPI = MUMBLE_API_CAST(api);

	pluginLog("Registered Mumble's API functions");
}


//////////////////////////////////////////////////////////////
///////////////////// OPTIONAL FUNCTIONS /////////////////////
//////////////////////////////////////////////////////////////
// The implementation of below functions is optional. If you don't need them, don't include them in your
// plugin

void mumble_setMumbleInfo(mumble_version_t mumbleVersion, mumble_version_t mumbleAPIVersion, mumble_version_t minimalExpectedAPIVersion) {
	// this function will always be the first one to be called. Even before init()
	// In here you can get info about the Mumble version this plugin is about to run in.
    mumble_version_t pluginVersion = mumble_getVersion();
    std::string pluginVersion_str = std::to_string(pluginVersion.major)+"."+std::to_string(pluginVersion.minor)+"."+std::to_string(pluginVersion.patch);
    std::string mumbleVersion_str = std::to_string(mumbleVersion.major)+"."+std::to_string(mumbleVersion.minor)+"."+std::to_string(mumbleVersion.patch);
    std::string mumbleAPIVersion_str = std::to_string(mumbleAPIVersion.major)+"."+std::to_string(mumbleAPIVersion.minor)+"."+std::to_string(mumbleAPIVersion.patch);
    std::string minimalExpectedAPIVersion_str = std::to_string(minimalExpectedAPIVersion.major)+"."+std::to_string(minimalExpectedAPIVersion.minor)+"."+std::to_string(minimalExpectedAPIVersion.patch);
    pluginLog("Plugin version: "              + pluginVersion_str
         + "; Mumble version: "               + mumbleVersion_str
         + "; Mumble API-Version: "           + mumbleAPIVersion_str
         + "; Minimal expected API-Version: " + minimalExpectedAPIVersion_str
    );

#ifdef DEBUG
        pluginLog("NOTICE: this is a debug build.");
#endif

}

mumble_version_t mumble_getVersion() {
	// Mumble uses semantic versioning (see https://semver.org/)
	// { major, minor, patch }
	return { FGCOM_VERSION_MAJOR, FGCOM_VERSION_MINOR, FGCOM_VERSION_PATCH };
}

MumbleStringWrapper mumble_getAuthor() {
    static const char *author = "Benedikt Hallinger";

    MumbleStringWrapper wrapper;
    wrapper.data = author;
    wrapper.size = strlen(author);
    wrapper.needsReleasing = false;  // It's a static String and therefore doesn't need releasing

    return wrapper;
}

MumbleStringWrapper mumble_getDescription() {
    const mumble_version_t version = mumble_getVersion();
    
    char *description = (char *)malloc(sizeof(char)*128);
    if (description != nullptr) {
        int len = sprintf(description,
            "FGCom-mumble %d.%d.%d provides an (aircraft) radio simulation.\n\nhttps://github.com/hbeni/fgcom-mumble",
            FGCOM_VERSION_MAJOR, FGCOM_VERSION_MINOR, FGCOM_VERSION_PATCH);
    } else {
        throw std::system_error();
    }

    MumbleStringWrapper wrapper;
    wrapper.data = description;
    wrapper.size = strlen(description);
    wrapper.needsReleasing = true;

    return wrapper;
}

uint32_t mumble_getFeatures() {
	// Tells Mumble whether this plugin delivers some known common functionality. See the PluginFeature enum in
	// PluginComponents_v_1_0_x.h for what is available.
	// If you want your plugin to deliver positional data, you'll want to return FEATURE_POSITIONAL
	//return FEATURE_NONE;
    return FEATURE_AUDIO;
}

uint32_t mumble_deactivateFeatures(uint32_t features) {
	pluginLog("Asked to deactivate feature set " + std::to_string(features));

	// All features that can't be deactivated should be returned
	return features;
}


void mumble_onServerConnected(mumble_connection_t connection) {
    pluginLog("Established server-connection with ID " + std::to_string(connection));
    
    // perform initialization if not done already (or missing parts of it;
    // particularly it will run the online part if the plugin was loaded when
    // we were not connected yet)
    activeConnection = connection;
    fgcom_initPlugin();    
    
}

void mumble_onServerDisconnected(mumble_connection_t connection) {
    pluginLog("Disconnected from server-connection with ID " + std::to_string(connection));
    
    fgcom_setPluginActive(false);
    activeConnection = -1;
}

void mumble_onServerSynchronized(mumble_connection_t connection) {
	// The client has finished synchronizing with the server. Thus we can now obtain a list of all users on this server
    // This is only called if the module was loaded during connecting time.
    // Sync status can be tested with isConnectionSynchronized()
	pluginLog("Server has finished synchronizing (ServerConnection: " + std::to_string(connection) + ")");

	size_t userCount;
	mumble_userid_t *userIDs;

	if (mumAPI.getAllUsers(ownPluginID, activeConnection, &userIDs, &userCount) != STATUS_OK) {
		pluginLog("[ERROR]: Can't obtain user list");
		return;
	}

	pluginLog("There are " + std::to_string(userCount) + " users on this server. Their names are:");

	for(size_t i=0; i<userCount; i++) {
		const char *userName;
		mumAPI.getUserName(ownPluginID, connection, userIDs[i], &userName);
		
		pluginLog("\t" + std::string(userName));

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
    pluginDbg("User with ID "+ std::to_string(userID) + " has joined channel with ID " + std::to_string(newChannelID) + ", coming from "+ std::to_string(previousChannelID) +". (ServerConnection: " + std::to_string(connection) + ")");
    
    if (userID == localMumId) {
        //stream << " OH! thats me! hello myself!";
        if (std::find(fgcom_specialChannelID.begin(), fgcom_specialChannelID.end(), newChannelID) != fgcom_specialChannelID.end()) {
            // We joined a special channel. Let's update all channel members and request their state
            pluginDbg("joined special channel, activating plugin functions");
            fgcom_setPluginActive(true);
            notifyRemotes(0, NTFY_ALL); // send our state to all users
            notifyRemotes(0, NTFY_ASK); // request all other state
        }
    } else {
        if (fgcom_isPluginActive()) {
            // Someone else joined this channel.
            // We should not send info to newly joined clients. The reason is, that we don't know if they have the plugin active already; so we will wait for them asking to send a NTFY_ASK packet.
            //pluginDbg("send state to freshly joined user");
            //notifyRemotes(0, NTFY_ALL, NTFY_ALL, userID);
        }
    }

}

void mumble_onChannelExited(mumble_connection_t connection, mumble_userid_t userID, mumble_channelid_t channelID) {
	pluginDbg("User with ID "+ std::to_string(userID) + " has left channel with ID " + std::to_string(channelID) + ". (ServerConnection: " + std::to_string(connection) + ")");
    
    //pluginDbg("userid="+std::to_string(userID)+"  mumid="+std::to_string(localMumId)+"  pluginActive="+std::to_string(fgcom_isPluginActive()));
    if (userID == localMumId && fgcom_isPluginActive()) {
        pluginLog("left special channel, deactivating plugin functions");
        fgcom_setPluginActive(false);
    }
    
}

// Called when any user changes his/her talking state.
// Handles the calculation of the PTT state that is sent to remotes.
void mumble_onUserTalkingStateChanged(mumble_connection_t connection, mumble_userid_t userID, mumble_talking_state_t talkingState) {
    pluginDbg("User with ID "+ std::to_string(userID) + " changed talking state: " + std::to_string(talkingState) + ". (ServerConnection: " + std::to_string(connection) + ")");
    bool mumble_talk_detected = talkingState == TALKING || talkingState == WHISPERING || talkingState == SHOUTING;

    // Current user is speaking. Either this activated trough the PTT button, or manually pushed mumble-ptt/voiceActivation
    if (userID == localMumId && fgcom_isPluginActive()) {
        // look if there is some PTT_REQ set.
        // If we have a PTT requested from the udp protocol, we are not activating the
        // radios configured to respond to mumbles talk state change.
        bool udp_protocol_ptt_detected = false;
        for (const auto &lcl_idty : fgcom_local_client) {
            int iid          = lcl_idty.first;
            fgcom_client lcl = lcl_idty.second;
            if (lcl.radios.size() > 0) {
                for (int radio_id=0; radio_id<lcl.radios.size(); radio_id++) {
                    if (lcl.radios[radio_id].ptt_req) udp_protocol_ptt_detected = true;
                }
            }
        }
        
        // update identities radios depending on config options
        fgcom_localcfg_mtx.lock();
        pluginDbg("  checking identities/radios for local users PTT...");
        for (const auto &lcl_idty : fgcom_local_client) {
            int iid          = lcl_idty.first;
            fgcom_client lcl = lcl_idty.second;
            if (lcl.radios.size() > 0) {
                for (int radio_id=0; radio_id<lcl.radios.size(); radio_id++) {
                    bool radio_ptt_req  = lcl.radios[radio_id].ptt_req; // requested from UDP state
                    auto radio_mapmumbleptt_srch = fgcom_cfg.mapMumblePTT.find(radio_id);
                    bool radio_mapmumbleptt = (radio_mapmumbleptt_srch != fgcom_cfg.mapMumblePTT.end())? radio_mapmumbleptt_srch->second : false;
                    pluginDbg("  IID="+std::to_string(iid)+"; radio_id="+std::to_string(radio_id)+"; operable="+std::to_string(lcl.radios[radio_id].operable));
                    pluginDbg("          radio_ptt_req="+std::to_string(radio_ptt_req));
                    pluginDbg("     radio_mapmumbleptt="+std::to_string(radio_mapmumbleptt));
                    for (const auto& cv : fgcom_cfg.mapMumblePTT) {
                        pluginDbg("    mapMumblePTT["+std::to_string(cv.first)+"]="+std::to_string(cv.second));
                    }
                    
                    bool oldValue = fgcom_local_client[iid].radios[radio_id].ptt;
                    bool newValue = false;
                    pluginDbg("                old_ptt="+std::to_string(oldValue));
                    pluginDbg("   mumble_talk_detected="+std::to_string(mumble_talk_detected));
                    if ( radio_ptt_req || !udp_protocol_ptt_detected && radio_mapmumbleptt ) {
                        // We should activate/deactivate PTT on the radio; either it's ptt was pressed in the UDP client, or we are configured for honoring mumbles talk state
                        newValue = mumble_talk_detected && lcl.radios[radio_id].operable;
                    }
                    pluginDbg("                new_ptt="+std::to_string(lcl.radios[radio_id].ptt));
                    
                    // broadcast changed PTT state to clients
                    fgcom_local_client[iid].radios[radio_id].ptt = newValue;
                    if (oldValue != newValue) {
                        pluginDbg("  COM"+std::to_string(radio_id+1)+" PTT changed: notifying remotes");
                        notifyRemotes(iid, NTFY_COM, radio_id);
                    }
                }
            }
        }
        fgcom_localcfg_mtx.unlock();
    }


    // some remote client is speaking.
    if (userID != localMumId && fgcom_isPluginActive() && mumble_talk_detected) {
        // check if we know this client, but don't have user data yet;
        // if so: request data update (workaround for https://github.com/hbeni/fgcom-mumble/issues/119)
        fgcom_client tmp_default = fgcom_client();
        
        fgcom_remotecfg_mtx.lock();
        auto search = fgcom_remote_clients.find(userID);
        if (search != fgcom_remote_clients.end()) {
            for (const auto &idty : fgcom_remote_clients[userID]) { // inspect all identites of the remote
                int rmt_iid      = idty.first;
                fgcom_client rmt = idty.second;
                
                bool isCallsignInitialized = rmt.callsign != tmp_default.callsign;
                bool isLocationInitialized = rmt.alt != tmp_default.alt || rmt.lat != tmp_default.lat || rmt.lon != tmp_default.lon;
                if ( !isCallsignInitialized || !isLocationInitialized ) {
                    // ATTENTION: Seeing this in the log indicates that there is a problem with the userdata synchronization process!
                    pluginLog("WARNING: known remote plugin user speaking, but no user data received so far: requesting it now");
                    notifyRemotes(0, NTFY_ASK); // request all other state
                }
            }
        }
        fgcom_remotecfg_mtx.unlock();
    }
}

// Note: Audio input is only possible with open mic. fgcom_hanldePTT() takes care of that.
bool mumble_onAudioInput(short *inputPCM, uint32_t sampleCount, uint16_t channelCount, bool isSpeech) {
	//pluginLog() << "Audio input with " << channelCount << " channels and " << sampleCount << " samples per channel encountered. IsSpeech: "
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

bool mumble_onAudioSourceFetched(float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRate, bool isSpeech, mumble_userid_t userID) {
	//std::ostream& stream = pluginLog() << "Audio output source with " << channelCount << " channels and " << sampleCount << " samples per channel fetched.";
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
    pluginDbg("mumble_onAudioSourceFetched(): plugin active="+std::to_string(fgcom_isPluginActive())+"; isSpeech="+std::to_string(isSpeech));
    bool rv = false;  // return value; false means the stream was not touched
    if (fgcom_isPluginActive() && isSpeech) {
        // This means, that the remote client was able to send, ie. his radio had power to transmit (or its a pluginless mumble client).
        pluginDbg("mumble_onAudioSourceFetched():   plugin active+speech detected from id="+std::to_string(userID));
        
        float bestSignalStrength = -1.0; // we want to get the connections signal strength.
        fgcom_radio matchedLocalRadio;
        bool isLandline = false;
        bool useRawData = false;
        
        // Fetch the remote clients data
        fgcom_remotecfg_mtx.lock();
        auto search = fgcom_remote_clients.find(userID);
        if (search != fgcom_remote_clients.end()) {
            // we found remote state.            
            for (const auto &idty : fgcom_remote_clients[userID]) { // inspect all identites of the remote
                int rmt_iid      = idty.first;
                fgcom_client rmt = idty.second;
            
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
                        for (const auto &lcl_idty : fgcom_local_client) { // inspect all identites of the local client
                            int iid          = lcl_idty.first;
                            fgcom_client lcl = lcl_idty.second;
                            pluginDbg("mumble_onAudioSourceFetched():     check local radios for frequency match (local iid="+std::to_string(iid)+")");
                            for (int lri=0; lri<lcl.radios.size(); lri++) {
                                pluginDbg("mumble_onAudioSourceFetched():     checking local radio #"+std::to_string(lri));
                                pluginDbg("mumble_onAudioSourceFetched():       frequency='"+lcl.radios[lri].frequency+"'");
                                pluginDbg("mumble_onAudioSourceFetched():       operable='"+std::to_string(lcl.radios[lri].operable)+"'");
                                pluginDbg("mumble_onAudioSourceFetched():       RDF='"+std::to_string(lcl.radios[lri].rdfEnabled)+"'");
                                pluginDbg("mumble_onAudioSourceFetched():       ptt='"+std::to_string(lcl.radios[lri].ptt)+"'");
                                pluginDbg("mumble_onAudioSourceFetched():       volume='"+std::to_string(lcl.radios[lri].volume)+"'");
                                
                                // skip check for "empty radios"
                                if (lcl.radios[lri].frequency == "") continue;
                                
                                // calculate frequency match
                                float signalMatchFilter;
                                fgcom_radiowave_freqConvRes rmt_frq_p = FGCom_radiowaveModel::splitFreqString(rmt.radios[ri].frequency);
                                std::unique_ptr<FGCom_radiowaveModel> radio_model_lcl(FGCom_radiowaveModel::selectModel(lcl.radios[lri].frequency));
                                std::unique_ptr<FGCom_radiowaveModel> radio_model_rmt(FGCom_radiowaveModel::selectModel(rmt.radios[ri].frequency));
                                if (radio_model_lcl->isCompatible(radio_model_rmt.get())) {
                                    signalMatchFilter = radio_model_lcl->getFrqMatch(lcl.radios[lri], rmt.radios[ri]);
                                    
                                } else {
                                    pluginDbg("mumble_onAudioSourceFetched():       radio models not compatible: lcl_type="+radio_model_lcl->getType()+"; rmt_type="+radio_model_rmt->getType());
                                    continue;
                                }
                                
                                
                                /* detect landline/intercom */
                                if (lcl.radios[lri].frequency.substr(0, 5) == "PHONE"
                                    && lcl.radios[lri].frequency == rmt.radios[ri].frequency && lcl.radios[lri].operable) {
                                    pluginDbg("mumble_onAudioSourceFetched():       local_radio="+std::to_string(lri)+"  PHONE mode detected");
                                    // Best quality, full-duplex mode
                                    matchedLocalRadio = lcl.radios[lri];
                                    bestSignalStrength = 1.0;
                                    isLandline = true;
                                    break; // no point in searching more
                                
                                
                                /* normal radio operation */
                                // (prefixed special frequencies never should be recieved!)
                                } else if (signalMatchFilter > 0.0 
                                    && lcl.radios[lri].operable
                                    && !lcl.radios[lri].ptt   // halfduplex!
                                    && rmt_frq_p.prefix.length() == 0) {
                                    pluginDbg("mumble_onAudioSourceFetched():       local_radio="+std::to_string(lri)+"  frequency "+lcl.radios[lri].frequency+" matches!");
                                    // we are listening on that frequency!
                                    // determine signal strenght for this connection
                                    fgcom_radiowave_signal signal = radio_model_lcl->getSignal(
                                        lcl.lat, lcl.lon, lcl.alt,
                                        rmt.lat, rmt.lon, rmt.alt,
                                        rmt.radios[ri].pwr);
                                    
                                    // apply signal filter from frequency match (miss-tuned will reduce the signal quality)
                                    signal.quality *= signalMatchFilter;
                                    
                                    pluginDbg("mumble_onAudioSourceFetched():       signalStrength="+std::to_string(signal.quality)
                                        +"; direction="+std::to_string(signal.direction)
                                        +"; angle="+std::to_string(signal.verticalAngle)
                                    );
                                
                                    
                                    // RDF: Updpate the radios signal information
                                    if (lcl.radios[lri].rdfEnabled && signal.quality > lcl.radios[lri].squelch) {
                                        pluginDbg("mumble_onAudioSourceFetched(): update signal data for RDF ("+std::to_string(rmt.mumid)+")="+rmt.callsign+", radio["+std::to_string(ri)+"]");
                                        //std::string rdfID = "rdf-"+rmt.callsign+":"+std::to_string(ri)+"-"+lcl.callsign+":"+std::to_string(lri);
                                        std::string rdfID = "rdf-"+rmt.callsign+":"+std::to_string(ri)+"-"+lcl.callsign;
                                        struct fgcom_rdfInfo rdfInfo = fgcom_rdfInfo();
                                        rdfInfo.txIdentity = rmt;
                                        rdfInfo.txRadio    = rmt.radios[ri];
                                        rdfInfo.rxIdentity = lcl;
                                        rdfInfo.rxRadio    = lcl.radios[lri];
                                        rdfInfo.rxRadioId  = lri+1;  // Radios indices start at 0, names start at 1.
                                        rdfInfo.signal     = signal;
                                        fgcom_rdf_registerSignal(rdfID, rdfInfo);
                                    }


                                    // See if the signal is better than the previous one.
                                    // As we have only one audio source stream per user, we want to apply the best
                                    // signal. If the remote station transmits with multiple radios, and we are tuned to more than
                                    // one, this will result in hearing the best signal quality of those available.
                                    if (signal.quality > lcl.radios[lri].squelch && signal.quality > bestSignalStrength) {
                                        // the signal is stronger than our squelch and tops the current last best signal
                                        bestSignalStrength = signal.quality;
                                        matchedLocalRadio  = lcl.radios[lri];
                                        pluginDbg("mumble_onAudioSourceFetched():         taking it, its better than the previous one");
                                    } else {
                                        pluginDbg("mumble_onAudioSourceFetched():         not taking it. squelch="+std::to_string(lcl.radios[lri].squelch)+", previousBestSignal="+std::to_string(bestSignalStrength));
                                    }
                                    
                                    
                                /* no match means, we had no operable mode for this radio pair */
                                } else {
                                    pluginDbg("mumble_onAudioSourceFetched():     nomatch");
                                }
                                
                                if (bestSignalStrength == 1.0) break; // no point in searching more
                            }
                        }
                    } else {
                        // the inspected remote radio did not PTT
                        pluginDbg("mumble_onAudioSourceFetched():     remote PTT OFF");
                    }
                }
            }
            
        } else {
            // we have no idea about the remote yet: 
            // (this may especially happen with sending clients without enabled plugin!)
            pluginDbg("mumble_onAudioSourceFetched():   sender with id="+std::to_string(userID)+" not found in remote state. muting stream.");
            if (fgcom_cfg.allowHearingNonPluginUsers) {
                // let audio trough unaffected
                useRawData = true;
            } else {
                // treat him as if hes not in range
                bestSignalStrength = 0.0;
            }
        }
        fgcom_remotecfg_mtx.unlock();
        
        
        // Now we got the connections signal strength.
        // It is either positive, or zero in case:
        //   - we did not have any info on the client
        //   - the client was out of range
        //   - we did not tune the frequency (or radio was broken, or radio squelch cut off)
#ifdef DEBUG
        // Debug code: Allow override of signal quality for debugging purposes
        if (fgcom_debug_signalstrength >= 0) {
            bestSignalStrength = fgcom_debug_signalstrength;
            pluginDbg("mumble_onAudioSourceFetched():   signalQuality debug override to "+std::to_string(fgcom_debug_signalstrength)+" in effect!");
        }
#endif

        rv = true;
        if (useRawData) {
            // we should use the raw audio packets unaffected
            pluginDbg("mumble_onAudioSourceFetched():   connected (use raw data)");
            rv = false;
            
        } else if (isLandline) {
            // we got a landline connection!
            pluginDbg("mumble_onAudioSourceFetched():   connected (phone)");
            fgcom_audio_makeMono(outputPCM, sampleCount, channelCount);
            if (fgcom_cfg.radioAudioEffects) fgcom_audio_filter(bestSignalStrength, outputPCM, sampleCount, channelCount, sampleRate);
            fgcom_audio_applyVolume(matchedLocalRadio.volume, outputPCM, sampleCount, channelCount);
            
        } else if (bestSignalStrength > 0.0) { 
            // we got a connection!
            pluginDbg("mumble_onAudioSourceFetched():   connected, bestSignalStrength="+std::to_string(bestSignalStrength));
            fgcom_audio_makeMono(outputPCM, sampleCount, channelCount);
            if (fgcom_cfg.radioAudioEffects) fgcom_audio_filter(bestSignalStrength, outputPCM, sampleCount, channelCount, sampleRate);
            if (fgcom_cfg.radioAudioEffects) fgcom_audio_addNoise(bestSignalStrength, outputPCM, sampleCount, channelCount);
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

bool mumble_onReceiveData(mumble_connection_t connection, mumble_userid_t sender, const uint8_t *data, size_t dataLength, const char *dataID) {
    pluginDbg("Received data with ID '"+std::string(dataID)+"' from user with ID '"+std::to_string(sender)+"'. Its length is '"+std::to_string(dataLength)+". (ServerConnection:"+std::to_string(connection)+")");

    if (dataLength > 0) {
        // if there is payload: handle it
        std::string data_string(reinterpret_cast<const char *>(data));   // We know that data is only a normal C-encoded String, so the reinterpret_cast is safe
        return handlePluginDataReceived(sender, std::string(dataID), data_string);
    }

    return false;
}



#ifndef NO_UPDATER
// updater in separate file
#include "updater.cpp"
#endif
