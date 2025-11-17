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
#include "io_plugin.h"

// FOR TESTING PURPOSES ONLY.
// This is a simple thread function that puts internal state to the terminal every second.
bool fgcom_isPluginActive();
bool fgcom_debugthread_shutdown = false;
bool fgcom_debugthread_running = false;
void debug_out_internal_state() {
    pluginDbg("---------STARTING DEBUG THREAD---------");
    fgcom_debugthread_running = true;
    
    while (!fgcom_debugthread_shutdown) {
        std::string state_str = "Internal state is as following:\n";
        state_str += "---------LOCAL STATE-----------\n";
        std::string pluginActive = fgcom_isPluginActive()? "active" : "inactive";
        state_str += "plugin state: "+ pluginActive + "\n";
        for (const auto &idty : fgcom_local_client) {
            int iid          = idty.first;
            fgcom_client lcl = idty.second;
            std::string lcl_prefix = "[mumid="+std::to_string(lcl.mumid)+"; iid="+std::to_string(iid)+"] "+lcl.callsign+": ";
            
            state_str += lcl_prefix + "location: LAT="+std::to_string(lcl.lat)+" LON="+std::to_string(lcl.lon)+" ALT="+std::to_string(lcl.alt)+"\n";
            state_str += lcl_prefix + "clientHostPort="+lcl.clientHost+":"+std::to_string(lcl.clientPort)+"\n";
            state_str += lcl_prefix + "clientTgtPort="+lcl.clientHost+":"+std::to_string(lcl.clientTgtPort)+"\n";
            
            std::time_t lastUpdate_t = std::chrono::system_clock::to_time_t(lcl.lastUpdate);
            std::string lastUpdate_str(30, '\0');
            std::strftime(&lastUpdate_str[0], lastUpdate_str.size(), "%H:%M:%S", std::localtime(&lastUpdate_t));
            lastUpdate_str.resize(strlen(lastUpdate_str.c_str()));
            state_str += lcl_prefix + "lastUpdate="+lastUpdate_str+"\n";
            
            state_str += lcl_prefix + std::to_string(lcl.radios.size()) + " radios registered\n";
            for (unsigned long int i=0; i<lcl.radios.size(); i++) {
                state_str += "  Radio "+std::to_string(i)+":   frequency='"+lcl.radios[i].frequency+"'\n";
                state_str += "  Radio "+std::to_string(i)+":   dialedFRQ='"+lcl.radios[i].dialedFRQ+"'\n";
                state_str += "  Radio "+std::to_string(i)+":   power_btn='"+std::to_string(lcl.radios[i].power_btn)+"'\n";
                state_str += "  Radio "+std::to_string(i)+":       volts='"+std::to_string(lcl.radios[i].volts)+"'\n";
                state_str += "  Radio "+std::to_string(i)+": serviceable='"+std::to_string(lcl.radios[i].serviceable)+"'\n";
                state_str += "  Radio "+std::to_string(i)+":    operable='"+std::to_string(lcl.radios[i].operable)+"'\n";
                state_str += "  Radio "+std::to_string(i)+":         ptt='"+std::to_string(lcl.radios[i].ptt)+"'\n";
                state_str += "  Radio "+std::to_string(i)+":     ptt_req='"+std::to_string(lcl.radios[i].ptt_req)+"'\n";
                state_str += "  Radio "+std::to_string(i)+":      volume='"+std::to_string(lcl.radios[i].volume)+"'\n";
                state_str += "  Radio "+std::to_string(i)+":         pwr='"+std::to_string(lcl.radios[i].pwr)+"'\n";
                state_str += "  Radio "+std::to_string(i)+":     squelch='"+std::to_string(lcl.radios[i].squelch)+"'\n";
                state_str += "  Radio "+std::to_string(i)+":  chan_width='"+std::to_string(lcl.radios[i].channelWidth)+"'\n";
                state_str += "  Radio "+std::to_string(i)+": RDF_enabled='"+std::to_string(lcl.radios[i].rdfEnabled)+"'\n";
                state_str += "  Radio "+std::to_string(i)+":     publish='"+std::to_string(lcl.radios[i].publish)+"'\n";
            }
        }
        
        state_str += "---------REMOTE STATE-----------\n";
        fgcom_remotecfg_mtx.lock();
        for (const auto &p : fgcom_remote_clients) {
            for (const auto &idty : fgcom_remote_clients[p.first]) {
                int iid          = idty.first;
                fgcom_client rmt = idty.second;
                std::string rmt_prefix = "[mumid="+std::to_string(rmt.mumid)+"; iid="+std::to_string(iid)+"] "+rmt.callsign+": ";
                
                state_str += rmt_prefix + "location: LAT="+std::to_string(rmt.lat)+" LON="+std::to_string(rmt.lon)+" ALT="+std::to_string(rmt.alt)+"\n";
                state_str += rmt_prefix + "clientHostPort="+rmt.clientHost+":"+std::to_string(rmt.clientPort)+"\n";
                
                std::time_t lastUpdate_t = std::chrono::system_clock::to_time_t(rmt.lastUpdate);
                std::string lastUpdate_str(30, '\0');
                std::strftime(&lastUpdate_str[0], lastUpdate_str.size(), "%H:%M:%S", std::localtime(&lastUpdate_t));
                lastUpdate_str.resize(strlen(lastUpdate_str.c_str()));
                state_str += rmt_prefix + "lastUpdate="+lastUpdate_str+"\n";
                
                std::time_t lastNotify_t = std::chrono::system_clock::to_time_t(rmt.lastNotification);
                std::string lastNotify_str(30, '\0');
                std::strftime(&lastNotify_str[0], lastNotify_str.size(), "%T", std::localtime(&lastNotify_t));
                lastNotify_str.resize(strlen(lastNotify_str.c_str()));
                state_str += rmt_prefix + "lastNotify="+lastNotify_str+"\n";
            
                state_str += rmt_prefix + std::to_string(rmt.radios.size()) + " radios registered\n";
                for (unsigned long int i=0; i<rmt.radios.size(); i++) {
                    state_str += "  Radio "+std::to_string(i)+":   frequency='"+rmt.radios[i].frequency+"'\n";
                    state_str += "  Radio "+std::to_string(i)+":   dialedFRQ='"+rmt.radios[i].dialedFRQ+"'\n";
                    //state_str += "  Radio "+std::to_string(i)+":   power_btn='"+std::to_string(rmt.radios[i].power_btn)+"'\n";
                    //state_str += "  Radio "+std::to_string(i)+":       volts='"+std::to_string(rmt.radios[i].volts)+"'\n";
                    //state_str += "  Radio "+std::to_string(i)+": serviceable='"+std::to_string(rmt.radios[i].serviceable)+"'\n";
                    state_str += "  Radio "+std::to_string(i)+":    operable='"+std::to_string(rmt.radios[i].operable)+"'\n";
                    state_str += "  Radio "+std::to_string(i)+":         ptt='"+std::to_string(rmt.radios[i].ptt)+"'\n";
                    //state_str += "  Radio "+std::to_string(i)+":      volume='"+std::to_string(rmt.radios[i].volume)+"'\n";
                    state_str += "  Radio "+std::to_string(i)+":         pwr='"+std::to_string(rmt.radios[i].pwr)+"'\n";
                    state_str += "  Radio "+std::to_string(i)+":    operable='"+std::to_string(rmt.radios[i].operable)+"'\n";
                    //state_str += "  Radio "+std::to_string(i)+":     squelch='"+std::to_string(rmt.radios[i].squelch)+"'\n";
                    //state_str += "  Radio "+std::to_string(i)+":  chan_width='"+std::to_string(rmt.radios[i].channelWidth)+"'\n";
                    //state_str += "  Radio "+std::to_string(i)+": RDF_enabled='"+std::to_string(rmt.radios[i].rdfEnabled)+"'\n";
                }
            }
        }
        fgcom_remotecfg_mtx.unlock();

        state_str += "--------------------------------\n";
        pluginDbg(state_str);

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    
    pluginDbg("---------DEBUG THREAD FINISHED---------");
    fgcom_debugthread_running = false;
}
 
