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

// FOR TESTING PURPOSES ONLY.
// This is a simple thread function that puts internal state to the terminal every second.
bool fgcom_isPluginActive();
void debug_out_internal_state() { 
    std::cout.setf(std::ios::unitbuf); // unbuffered cout writes
    
    while (true) {
        std::cout << "---------LOCAL STATE-----------\n";
        printf("plugin state: %s\n", (fgcom_isPluginActive())?"active":"inactive");
        for (const auto &idty : fgcom_local_client) {
            int iid          = idty.first;
            fgcom_client lcl = idty.second;
            printf("[mumid=%i; iid=%i] %s: location: LAT=%f LON=%f ALT=%f\n", lcl.mumid, iid, lcl.callsign.c_str(), lcl.lat, lcl.lon, lcl.alt);
            printf("[mumid=%i; iid=%i] %s: clientPort=%i\n", lcl.mumid, iid, lcl.callsign.c_str(), lcl.clientPort);
            
            std::time_t lastUpdate_t = std::chrono::system_clock::to_time_t(lcl.lastUpdate);
            std::string lastUpdate_str(30, '\0');
            std::strftime(&lastUpdate_str[0], lastUpdate_str.size(), "%T", std::localtime(&lastUpdate_t));
            printf("[mumid=%i; iid=%i] %s: lastUpdate=%s\n", lcl.mumid, iid, lcl.callsign.c_str(), lastUpdate_str.c_str());
            
            printf("[mumid=%i; iid=%i] %s: %i radios registered\n", lcl.mumid, iid, lcl.callsign.c_str(), lcl.radios.size());
            if (lcl.radios.size() > 0) {
                for (int i=0; i<lcl.radios.size(); i++) {
                    printf("  Radio %i:   frequency='%s'\n", i, lcl.radios[i].frequency.c_str());
                    printf("  Radio %i:   power_btn=%i'\n", i, lcl.radios[i].power_btn);
                    printf("  Radio %i:       volts=%f\n", i, lcl.radios[i].volts);
                    printf("  Radio %i: serviceable=%i\n", i, lcl.radios[i].serviceable);
                    printf("  Radio %i: => operable=%i\n", i, fgcom_radio_isOperable(lcl.radios[i]));
                    printf("  Radio %i:         ptt=%i\n", i, lcl.radios[i].ptt);
                    printf("  Radio %i:      volume=%f\n", i, lcl.radios[i].volume);
                    printf("  Radio %i:         pwr=%f\n", i, lcl.radios[i].pwr);
                    printf("  Radio %i:     squelch=%f\n", i, lcl.radios[i].squelch);
                    printf("  Radio %i: RDF_enabled=%i\n", i, lcl.radios[i].rdfEnabled);
                }
            }
        }
        
        std::cout << "---------REMOTE STATE-----------\n";
        fgcom_remotecfg_mtx.lock();
        for (const auto &p : fgcom_remote_clients) {
            for (const auto &idty : fgcom_remote_clients[p.first]) {
                int iid          = idty.first;
                fgcom_client rmt = idty.second;
                printf("[id=%i; mumid=%i; iid=%i] %s: location: LAT=%f LON=%f ALT=%f\n", p.first, rmt.mumid, iid, rmt.callsign.c_str(), rmt.lat, rmt.lon, rmt.alt);
                printf("[id=%i; mumid=%i; iid=%i] %s: %i radios registered\n", p.first, rmt.mumid, iid, rmt.callsign.c_str(), rmt.radios.size());
                printf("[mumid=%i; iid=%i] %s: clientPort=%i\n", rmt.mumid, iid, rmt.callsign.c_str(), rmt.clientPort);
                
                std::time_t lastUpdate_t = std::chrono::system_clock::to_time_t(rmt.lastUpdate);
                std::string lastUpdate_str(30, '\0');
                std::strftime(&lastUpdate_str[0], lastUpdate_str.size(), "%T", std::localtime(&lastUpdate_t));
                printf("[mumid=%i; iid=%i] %s: lastUpdate=%s\n", rmt.mumid, iid, rmt.callsign.c_str(), lastUpdate_str.c_str());
            
                if (rmt.radios.size() > 0) {
                    for (int i=0; i<rmt.radios.size(); i++) {
                        printf("  Radio %i:   frequency='%s'\n", i, rmt.radios[i].frequency.c_str());
                        printf("  Radio %i:   power_btn=%i\n", i, rmt.radios[i].power_btn);
                        printf("  Radio %i:       volts=%f\n", i, rmt.radios[i].volts);
                        printf("  Radio %i: serviceable=%i\n", i, rmt.radios[i].serviceable);
                        printf("  Radio %i: => operable=%i\n", i, fgcom_radio_isOperable(rmt.radios[i]));
                        printf("  Radio %i:         ptt=%i\n", i, rmt.radios[i].ptt);
                        printf("  Radio %i:      volume=%f\n", i, rmt.radios[i].volume);
                        printf("  Radio %i:         pwr=%f\n", i, rmt.radios[i].pwr);
                        printf("  Radio %i:     squelch=%f\n", i, rmt.radios[i].squelch);
                        printf("  Radio %i: RDF_enabled=%i\n", i, rmt.radios[i].rdfEnabled);
                    }
                }
            }
        }
        fgcom_remotecfg_mtx.unlock();
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    
}
 
